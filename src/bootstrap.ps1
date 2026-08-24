<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

$script:ToolchainRegistryImage = 'registry@sha256:1be55279f18a2fe1a74edf2664cac61c1bea305b7b4642dab412e7affdcb3e33'
$script:ToolchainGitImage = 'gitea/gitea@sha256:36cce26be71609091e1236d5b5de2c66a81fb8a7d45756a5fd3b7a28c11733b7'
$script:ToolchainRegistryNodePort = 31999

function ConvertTo-ToolchainBootstrapYamlString {
	param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
	if ($Value.IndexOf([char]0) -ge 0 -or $Value -match '[\r\n]') { throw 'bootstrap value contains unsupported control characters' }
	return "'$($Value.Replace("'", "''"))'"
}

function Get-ToolchainBootstrapAgentImage {
	$module = Get-Module -Name Toolchain | Select-Object -First 1
	$version = if ($module -and $module.Version) { [string]$module.Version } else {
		$versionPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'VERSION'
		if (Test-Path -LiteralPath $versionPath -PathType Leaf) { (Get-Content -LiteralPath $versionPath -Raw).Trim() } else { 'dev' }
	}
	return "ghcr.io/allsagetech/toolchain-agent:$version"
}

function New-ToolchainBootstrapPassword {
	$bytes = New-Object byte[] 32
	$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
	try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
	return ([Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'))
}

function Get-ToolchainBootstrapSecretValue {
	param(
		[Parameter(Mandatory)][string]$Kubectl,
		[string]$Kubeconfig,
		[Parameter(Mandatory)][string]$Secret,
		[Parameter(Mandatory)][string]$Key
	)
	$result = Invoke-ToolchainBootstrapKubectl -Kubectl $Kubectl -Kubeconfig $Kubeconfig -Arguments @(
		'get', "secret/$Secret", '-n', 'toolchain-system', '--ignore-not-found', '-o', "jsonpath={.data.$Key}"
	)
	$encoded = ($result.Output -join '').Trim()
	if (-not $encoded) { return $null }
	try { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)) }
	catch { throw "invalid Toolchain bootstrap secret '$Secret/$Key': $($_.Exception.Message)" }
}

function Resolve-ToolchainBootstrapKubeconfig {
	param([string]$Name, [string]$Kubeconfig)
	if ($Name -and $Kubeconfig) { throw 'cluster init accepts either a managed cluster name or -Kubeconfig, not both' }
	if ($Name) {
		$state = Read-ToolchainClusterState -Name $Name
		if (-not $state) { throw "Toolchain cluster not found: $Name" }
		$status = Get-ToolchainClusterRuntimeStatus -State $state
		if ($status -ne 'Running') { throw "Toolchain cluster '$Name' is not running (status: $status)" }
		Sync-ToolchainClusterKubeconfig -State $state
		$Kubeconfig = Get-ToolchainClusterKubeconfigPath -Name $Name
	}
	if (-not $Kubeconfig) { return $null }
	$path = [IO.Path]::GetFullPath($Kubeconfig)
	if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "cluster kubeconfig is not a file: $path" }
	return $path
}

function Get-ToolchainBootstrapApiServer {
	param([string]$Kubeconfig)

	if (-not $Kubeconfig -or -not (Test-Path -LiteralPath $Kubeconfig -PathType Leaf)) { return 'the current Kubernetes context' }
	foreach ($line in [IO.File]::ReadLines($Kubeconfig)) {
		if ($line -match '^\s*server:\s*(?<Server>\S+)\s*$') {
			return $Matches.Server.Trim('''', '"')
		}
	}
	return "the API endpoint in '$Kubeconfig'"
}

function Invoke-ToolchainBootstrapKubectl {
	param(
		[Parameter(Mandatory)][string]$Kubectl,
		[string]$Kubeconfig,
		[Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments,
		[switch]$AllowFailure
	)
	$allArguments = @()
	if ($Kubeconfig) { $allArguments += @('--kubeconfig', $Kubeconfig) }
	$allArguments += $Arguments
	return (Invoke-ToolchainClusterProcess -FilePath $Kubectl -Arguments $allArguments -AllowFailure:$AllowFailure)
}

function New-ToolchainBootstrapManifest {
	param(
		[Parameter(Mandatory)][string]$AgentImage,
		[Parameter(Mandatory)][string]$RegistryImage,
		[Parameter(Mandatory)][string]$GitImage,
		[Parameter(Mandatory)][ValidateSet('all', 'labeled')][string]$AgentMutationPolicy,
		[Parameter(Mandatory)][hashtable]$RegistryAuth,
		[hashtable]$GitAdminAuth,
		[ValidateRange(30000, 32767)][int]$RegistryNodePort = $script:ToolchainRegistryNodePort,
		[string[]]$Components,
		[string]$MappingsJson = '{}',
		[string]$StorageClass,
		[ValidatePattern('^[1-9][0-9]*(?:Mi|Gi|Ti)$')][string]$RegistryStorage = '20Gi',
		[ValidatePattern('^[1-9][0-9]*(?:Mi|Gi|Ti)$')][string]$GitStorage = '10Gi'
	)
	foreach ($image in @($AgentImage, $RegistryImage, $GitImage)) { Assert-ToolchainClusterImage -Image $image }
	if (-not $RegistryAuth.Username -or -not $RegistryAuth.Password) { throw 'RegistryAuth requires Username and Password values' }
	try { $mappings = $MappingsJson | ConvertFrom-Json }
	catch { throw "invalid existing Toolchain image mappings: $($_.Exception.Message)" }
	if ($null -eq $mappings -or $mappings -is [array] -or $mappings -is [string] -or $mappings -is [ValueType]) { throw 'existing Toolchain image mappings must be a JSON object' }
	$agentImageValue = ConvertTo-ToolchainBootstrapYamlString $AgentImage
	$registryImageValue = ConvertTo-ToolchainBootstrapYamlString $RegistryImage
	$policyValue = ConvertTo-ToolchainBootstrapYamlString $AgentMutationPolicy
	$registryUsernameValue = ConvertTo-ToolchainBootstrapYamlString ([string]$RegistryAuth.Username)
	$registryPasswordValue = ConvertTo-ToolchainBootstrapYamlString ([string]$RegistryAuth.Password)
	$registryStorageValue = ConvertTo-ToolchainBootstrapYamlString $RegistryStorage
	$storageClassLine = if ($StorageClass) { "  storageClassName: $(ConvertTo-ToolchainBootstrapYamlString $StorageClass)`n" } else { '' }
	$state = [ordered]@{
		schemaVersion = 1
		registryAddress = "127.0.0.1:$RegistryNodePort"
		registryService = 'toolchain-registry.toolchain-system.svc:5000'
		registryPushSecret = 'toolchain-registry-credentials'
		agentMutationPolicy = $AgentMutationPolicy
		components = @($Components)
	} | ConvertTo-Json -Compress
	$stateValue = ConvertTo-ToolchainBootstrapYamlString $state
	$mappingsValue = ConvertTo-ToolchainBootstrapYamlString $MappingsJson

	$manifest = @"
apiVersion: v1
kind: Namespace
metadata:
  name: toolchain-system
  labels:
    app.kubernetes.io/managed-by: toolchain
    toolchain.dev/agent: ignore
---
apiVersion: v1
kind: Secret
metadata:
  name: toolchain-state
  namespace: toolchain-system
  labels:
    app.kubernetes.io/managed-by: toolchain
type: Opaque
stringData:
  state.json: $stateValue
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: toolchain-image-mappings
  namespace: toolchain-system
  labels:
    app.kubernetes.io/managed-by: toolchain
data:
  mappings.json: $mappingsValue
---
apiVersion: v1
kind: Secret
metadata:
  name: toolchain-registry-credentials
  namespace: toolchain-system
  labels:
    app.kubernetes.io/managed-by: toolchain
type: Opaque
stringData:
  username: $registryUsernameValue
  password: $registryPasswordValue
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: toolchain-registry
  namespace: toolchain-system
  labels:
    app.kubernetes.io/name: toolchain-registry
    app.kubernetes.io/managed-by: toolchain
spec:
$storageClassLine  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: $registryStorageValue
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: toolchain-registry
  namespace: toolchain-system
  labels:
    app.kubernetes.io/name: toolchain-registry
    app.kubernetes.io/managed-by: toolchain
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: toolchain-registry
  template:
    metadata:
      labels:
        app.kubernetes.io/name: toolchain-registry
        toolchain.dev/agent: ignore
    spec:
      automountServiceAccountToken: false
      securityContext:
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: registry
          image: $registryImageValue
          imagePullPolicy: IfNotPresent
          env:
            - name: REGISTRY_HTTP_ADDR
              value: '0.0.0.0:5000'
            - name: REGISTRY_STORAGE_DELETE_ENABLED
              value: 'true'
            - name: REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY
              value: '/var/lib/registry'
          ports:
            - name: registry
              containerPort: 5000
          readinessProbe:
            httpGet:
              path: /v2/
              port: registry
            initialDelaySeconds: 2
            periodSeconds: 5
          livenessProbe:
            httpGet:
              path: /v2/
              port: registry
            initialDelaySeconds: 10
            periodSeconds: 10
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: '2'
              memory: 1Gi
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ['ALL']
            runAsNonRoot: true
            runAsUser: 1000
            runAsGroup: 2000
          volumeMounts:
            - name: storage
              mountPath: /var/lib/registry
      volumes:
        - name: storage
          persistentVolumeClaim:
            claimName: toolchain-registry
---
apiVersion: v1
kind: Service
metadata:
  name: toolchain-registry
  namespace: toolchain-system
  labels:
    app.kubernetes.io/name: toolchain-registry
    app.kubernetes.io/managed-by: toolchain
spec:
  selector:
    app.kubernetes.io/name: toolchain-registry
  ports:
    - name: registry
      port: 5000
      targetPort: registry
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: toolchain-registry
  namespace: toolchain-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: toolchain-registry
  policyTypes: ['Ingress']
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: toolchain-system
          podSelector:
            matchLabels:
              app.kubernetes.io/name: toolchain-registry-gateway
      ports:
        - protocol: TCP
          port: 5000
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: toolchain-registry-gateway
  namespace: toolchain-system
  labels:
    app.kubernetes.io/name: toolchain-registry-gateway
    app.kubernetes.io/managed-by: toolchain
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: toolchain-registry-gateway
  template:
    metadata:
      labels:
        app.kubernetes.io/name: toolchain-registry-gateway
        toolchain.dev/agent: ignore
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: gateway
          image: $agentImageValue
          imagePullPolicy: IfNotPresent
          env:
            - name: TOOLCHAIN_MODE
              value: registry-gateway
            - name: TOOLCHAIN_REGISTRY_UPSTREAM
              value: http://toolchain-registry.toolchain-system.svc:5000
            - name: TOOLCHAIN_REGISTRY_USERNAME
              valueFrom:
                secretKeyRef:
                  name: toolchain-registry-credentials
                  key: username
            - name: TOOLCHAIN_REGISTRY_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: toolchain-registry-credentials
                  key: password
          ports:
            - name: registry
              containerPort: 5000
          readinessProbe:
            httpGet:
              path: /readyz
              port: registry
            periodSeconds: 2
          livenessProbe:
            httpGet:
              path: /healthz
              port: registry
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: 25m
              memory: 32Mi
            limits:
              cpu: 250m
              memory: 128Mi
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ['ALL']
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
---
apiVersion: v1
kind: Service
metadata:
  name: toolchain-registry-gateway
  namespace: toolchain-system
  labels:
    app.kubernetes.io/name: toolchain-registry-gateway
    app.kubernetes.io/managed-by: toolchain
spec:
  type: NodePort
  selector:
    app.kubernetes.io/name: toolchain-registry-gateway
  ports:
    - name: registry
      port: 5000
      targetPort: registry
      nodePort: $RegistryNodePort
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: toolchain-agent
  namespace: toolchain-system
  labels:
    app.kubernetes.io/managed-by: toolchain
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: toolchain-agent
  labels:
    app.kubernetes.io/managed-by: toolchain
rules:
  - apiGroups: ['admissionregistration.k8s.io']
    resources: ['mutatingwebhookconfigurations']
    resourceNames: ['toolchain-agent']
    verbs: ['get', 'patch']
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: toolchain-agent
  labels:
    app.kubernetes.io/managed-by: toolchain
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: toolchain-agent
subjects:
  - kind: ServiceAccount
    name: toolchain-agent
    namespace: toolchain-system
---
apiVersion: v1
kind: Service
metadata:
  name: toolchain-agent
  namespace: toolchain-system
  labels:
    app.kubernetes.io/name: toolchain-agent
    app.kubernetes.io/managed-by: toolchain
spec:
  selector:
    app.kubernetes.io/name: toolchain-agent
  ports:
    - name: https
      port: 443
      targetPort: https
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: toolchain-agent
  namespace: toolchain-system
  labels:
    app.kubernetes.io/name: toolchain-agent
    app.kubernetes.io/managed-by: toolchain
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: toolchain-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: toolchain-agent
        toolchain.dev/agent: ignore
    spec:
      serviceAccountName: toolchain-agent
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: agent
          image: $agentImageValue
          imagePullPolicy: IfNotPresent
          env:
            - name: TOOLCHAIN_MAPPINGS_PATH
              value: /etc/toolchain-agent/mappings.json
            - name: TOOLCHAIN_MUTATION_POLICY
              value: $policyValue
          ports:
            - name: https
              containerPort: 8443
          readinessProbe:
            httpGet:
              scheme: HTTPS
              path: /readyz
              port: https
            periodSeconds: 2
          livenessProbe:
            httpGet:
              scheme: HTTPS
              path: /healthz
              port: https
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: 25m
              memory: 32Mi
            limits:
              cpu: 250m
              memory: 128Mi
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ['ALL']
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
          volumeMounts:
            - name: mappings
              mountPath: /etc/toolchain-agent
              readOnly: true
      volumes:
        - name: mappings
          configMap:
            name: toolchain-image-mappings
---
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: toolchain-agent
  labels:
    app.kubernetes.io/managed-by: toolchain
webhooks:
  - name: pods.agent.toolchain.dev
    admissionReviewVersions: ['v1']
    sideEffects: None
    failurePolicy: Ignore
    matchPolicy: Equivalent
    reinvocationPolicy: IfNeeded
    timeoutSeconds: 5
    clientConfig:
      caBundle: ''
      service:
        name: toolchain-agent
        namespace: toolchain-system
        path: /mutate
        port: 443
    namespaceSelector:
      matchExpressions:
        - key: toolchain.dev/agent
          operator: NotIn
          values: ['ignore']
    rules:
      - apiGroups: ['']
        apiVersions: ['v1']
        operations: ['CREATE']
        resources: ['pods']
        scope: Namespaced
"@

	if ('git-server' -in @($Components)) {
		if (-not $GitAdminAuth.Username -or -not $GitAdminAuth.Password) { throw 'GitAdminAuth requires Username and Password values when the git-server component is selected' }
		$gitImageValue = ConvertTo-ToolchainBootstrapYamlString $GitImage
		$gitStorageValue = ConvertTo-ToolchainBootstrapYamlString $GitStorage
		$gitUsernameValue = ConvertTo-ToolchainBootstrapYamlString ([string]$GitAdminAuth.Username)
		$gitPasswordValue = ConvertTo-ToolchainBootstrapYamlString ([string]$GitAdminAuth.Password)
		$gitStorageClassLine = if ($StorageClass) { "  storageClassName: $(ConvertTo-ToolchainBootstrapYamlString $StorageClass)`n" } else { '' }
		$manifest += @"
---
apiVersion: v1
kind: Secret
metadata:
  name: toolchain-git-admin
  namespace: toolchain-system
  labels:
    app.kubernetes.io/managed-by: toolchain
type: Opaque
stringData:
  TOOLCHAIN_GIT_ADMIN_USER: $gitUsernameValue
  TOOLCHAIN_GIT_ADMIN_PASSWORD: $gitPasswordValue
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: toolchain-git-config
  namespace: toolchain-system
  labels:
    app.kubernetes.io/managed-by: toolchain
data:
  GITEA__database__DB_TYPE: sqlite3
  GITEA__server__DOMAIN: toolchain-git.toolchain-system.svc
  GITEA__server__ROOT_URL: http://toolchain-git.toolchain-system.svc:3000/
  GITEA__server__START_SSH_SERVER: 'true'
  GITEA__server__SSH_PORT: '22'
  GITEA__server__SSH_LISTEN_PORT: '2222'
  GITEA__security__INSTALL_LOCK: 'true'
  GITEA__service__DISABLE_REGISTRATION: 'true'
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: toolchain-git
  namespace: toolchain-system
  labels:
    app.kubernetes.io/name: toolchain-git
    app.kubernetes.io/managed-by: toolchain
spec:
$gitStorageClassLine  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: $gitStorageValue
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: toolchain-git-config
  namespace: toolchain-system
  labels:
    app.kubernetes.io/name: toolchain-git
    app.kubernetes.io/managed-by: toolchain
spec:
$gitStorageClassLine  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: '1Gi'
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: toolchain-git
  namespace: toolchain-system
  labels:
    app.kubernetes.io/name: toolchain-git
    app.kubernetes.io/managed-by: toolchain
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: toolchain-git
  template:
    metadata:
      labels:
        app.kubernetes.io/name: toolchain-git
        toolchain.dev/agent: ignore
    spec:
      automountServiceAccountToken: false
      securityContext:
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        - name: migrate
          image: $gitImageValue
          imagePullPolicy: IfNotPresent
          args: ['/usr/local/bin/gitea', '-c', '/etc/gitea/app.ini', 'migrate']
          envFrom:
            - configMapRef:
                name: toolchain-git-config
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ['ALL']
            runAsNonRoot: true
            runAsUser: 1000
            runAsGroup: 1000
          volumeMounts:
            - name: storage
              mountPath: /var/lib/gitea
            - name: config
              mountPath: /etc/gitea
        - name: ensure-admin
          image: $gitImageValue
          imagePullPolicy: IfNotPresent
          args:
            - /bin/sh
            - -ec
            - |
              if /usr/local/bin/gitea -c /etc/gitea/app.ini admin user create --admin --username "`$TOOLCHAIN_GIT_ADMIN_USER" --password "`$TOOLCHAIN_GIT_ADMIN_PASSWORD" --email toolchain-admin@localhost.invalid --must-change-password=false; then
                exit 0
              fi
              /usr/local/bin/gitea -c /etc/gitea/app.ini admin user list | grep -Fq "`$TOOLCHAIN_GIT_ADMIN_USER"
          envFrom:
            - configMapRef:
                name: toolchain-git-config
            - secretRef:
                name: toolchain-git-admin
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ['ALL']
            runAsNonRoot: true
            runAsUser: 1000
            runAsGroup: 1000
          volumeMounts:
            - name: storage
              mountPath: /var/lib/gitea
            - name: config
              mountPath: /etc/gitea
      containers:
        - name: gitea
          image: $gitImageValue
          imagePullPolicy: IfNotPresent
          envFrom:
            - configMapRef:
                name: toolchain-git-config
          ports:
            - name: http
              containerPort: 3000
            - name: ssh
              containerPort: 2222
          readinessProbe:
            httpGet:
              path: /api/healthz
              port: http
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: '2'
              memory: 1Gi
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ['ALL']
            runAsNonRoot: true
            runAsUser: 1000
            runAsGroup: 1000
          volumeMounts:
            - name: storage
              mountPath: /var/lib/gitea
            - name: config
              mountPath: /etc/gitea
      volumes:
        - name: storage
          persistentVolumeClaim:
            claimName: toolchain-git
        - name: config
          persistentVolumeClaim:
            claimName: toolchain-git-config
---
apiVersion: v1
kind: Service
metadata:
  name: toolchain-git
  namespace: toolchain-system
  labels:
    app.kubernetes.io/name: toolchain-git
    app.kubernetes.io/managed-by: toolchain
spec:
  selector:
    app.kubernetes.io/name: toolchain-git
  ports:
    - name: http
      port: 3000
      targetPort: http
    - name: ssh
      port: 22
      targetPort: ssh
"@
	}
	return $manifest
}

function Select-ToolchainClusterInitComponents {
	[CmdletBinding()]
	param()

	while ($true) {
		try {
			$response = Read-Host 'Initialize optional Git server? [y/N]'
		} catch {
			throw "component selection requires interactive input; rerun with '-Components git-server' or '-Components none'"
		}
		$answer = if ($null -eq $response) { '' } else { ([string]$response).Trim().ToLowerInvariant() }
		if (-not $answer -or $answer -in @('n', 'no')) { return }
		if ($answer -in @('y', 'yes')) { return 'git-server' }
		Write-Warning "Please answer 'y' or 'n'."
	}
}

function Invoke-ToolchainClusterInit {
	[CmdletBinding()]
	param(
		[string]$Name,
		[string]$Kubeconfig,
		[switch]$Confirm,
		[ValidateSet('git-server', 'none')][string[]]$Components,
		[switch]$PromptForComponents,
		[ValidateSet('all', 'labeled')][string]$AgentMutationPolicy = 'labeled',
		[string]$AgentImage = (Get-ToolchainBootstrapAgentImage),
		[switch]$BuildLocalAgent,
		[string]$RegistryImage = $script:ToolchainRegistryImage,
		[string]$GitImage = $script:ToolchainGitImage,
		[string]$StorageClass,
		[ValidatePattern('^[1-9][0-9]*(?:Mi|Gi|Ti)$')][string]$RegistryStorage = '20Gi',
		[ValidatePattern('^[1-9][0-9]*(?:Mi|Gi|Ti)$')][string]$GitStorage = '10Gi',
		[ValidateRange(30000, 32767)][int]$RegistryNodePort = $script:ToolchainRegistryNodePort,
		[ValidateRange(30, 1800)][int]$WaitSeconds = 600,
		[switch]$PassThru
	)
	if (-not $Confirm) { throw "cluster init changes Kubernetes cluster state; rerun with -Confirm after reviewing 'tlc cluster init help'" }
	if ($PromptForComponents -or -not $PSBoundParameters.ContainsKey('Components')) {
		$Components = @(Select-ToolchainClusterInitComponents)
	}
	$componentsRequested = @($Components | Where-Object { $_ } | Sort-Object -Unique)
	if ('none' -in $componentsRequested -and $componentsRequested.Count -gt 1) {
		throw "component 'none' cannot be combined with another component"
	}
	$componentsNormalized = @($componentsRequested | Where-Object { $_ -ne 'none' })
	$kubeconfigPath = Resolve-ToolchainBootstrapKubeconfig -Name $Name -Kubeconfig $Kubeconfig
	$kubectl = Get-ToolchainClusterExecutable -Name kubectl -Package kubectl -InstallHint 'Install kubectl and ensure its executable is available on PATH.'
	$apiServer = Get-ToolchainBootstrapApiServer -Kubeconfig $kubeconfigPath
	$target = if ($Name) { "Toolchain cluster '$Name'" } else { 'the selected Kubernetes context' }
	try {
		$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('get', '--request-timeout=10s', '--raw=/readyz')
	} catch {
		throw "Kubernetes API preflight failed for $target at $apiServer. Confirm the provider is running and the endpoint is reachable. kubectl reported: $($_.Exception.Message)"
	}
	$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('get', '--request-timeout=10s', 'namespace', 'kube-system', '-o', 'name')
	if ($BuildLocalAgent) {
		if (-not $Name) { throw 'local agent builds require a Toolchain-managed cluster name' }
		$AgentImage = Publish-ToolchainLocalAgentImage -Name $Name
	}
	$mappingResult = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @(
		'get', 'configmap/toolchain-image-mappings', '-n', 'toolchain-system', '--ignore-not-found', '-o', 'jsonpath={.data.mappings\.json}'
	)
	$mappingsJson = ($mappingResult.Output -join '').Trim()
	if (-not $mappingsJson) { $mappingsJson = '{}' }
	$registryUsername = 'toolchain-push'
	$registryPassword = Get-ToolchainBootstrapSecretValue -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Secret 'toolchain-registry-credentials' -Key 'password'
	if (-not $registryPassword) { $registryPassword = New-ToolchainBootstrapPassword }
	$gitUsername = 'toolchain-admin'
	$gitPassword = $null
	if ('git-server' -in $componentsNormalized) {
		$gitPassword = Get-ToolchainBootstrapSecretValue -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Secret 'toolchain-git-admin' -Key 'TOOLCHAIN_GIT_ADMIN_PASSWORD'
		if (-not $gitPassword) { $gitPassword = New-ToolchainBootstrapPassword }
	}
	$registryAuth = @{ Username = $registryUsername; Password = $registryPassword }
	$gitAdminAuth = if ($gitPassword) { @{ Username = $gitUsername; Password = $gitPassword } } else { $null }

	$manifest = New-ToolchainBootstrapManifest -AgentImage $AgentImage -RegistryImage $RegistryImage -GitImage $GitImage `
		-AgentMutationPolicy $AgentMutationPolicy -RegistryAuth $registryAuth -GitAdminAuth $gitAdminAuth `
		-RegistryNodePort $RegistryNodePort -Components $componentsNormalized `
		-MappingsJson $mappingsJson -StorageClass $StorageClass -RegistryStorage $RegistryStorage -GitStorage $GitStorage
	# GetTempFileName creates the file atomically and with owner-only permissions
	# on Unix, which matters because this manifest contains generated Secrets.
	$temp = [IO.Path]::GetTempFileName()
	try {
		Write-ToolchainClusterTextFile -Path $temp -Content $manifest
		$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('apply', '--server-side', '--field-manager=toolchain', '-f', $temp)
	} finally {
		if (Test-Path -LiteralPath $temp -PathType Leaf) { [IO.File]::Delete($temp) }
	}

	$timeout = "${WaitSeconds}s"
	$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('rollout', 'restart', 'deployment/toolchain-agent', '-n', 'toolchain-system')
	$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('rollout', 'status', 'deployment/toolchain-registry', '-n', 'toolchain-system', "--timeout=$timeout")
	$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('rollout', 'status', 'deployment/toolchain-registry-gateway', '-n', 'toolchain-system', "--timeout=$timeout")
	$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('rollout', 'status', 'deployment/toolchain-agent', '-n', 'toolchain-system', "--timeout=$timeout")
	if ('git-server' -in $componentsNormalized) {
		$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('rollout', 'status', 'deployment/toolchain-git', '-n', 'toolchain-system', "--timeout=$timeout")
	}
	$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('get', 'secret/toolchain-state', '-n', 'toolchain-system', '-o', 'name')
	$result = [pscustomobject]@{
		PSTypeName = 'Toolchain.ClusterInitialization'
		Cluster = if ($Name) { $Name } else { 'current-context' }
		Kubeconfig = $kubeconfigPath
		Namespace = 'toolchain-system'
		Registry = "127.0.0.1:$RegistryNodePort"
		RegistryCredentialSecret = 'toolchain-registry-credentials'
		AgentMutationPolicy = $AgentMutationPolicy
		Components = $componentsNormalized
		GitUsername = if ('git-server' -in $componentsNormalized) { $gitUsername } else { $null }
		GitCredentialSecret = if ('git-server' -in $componentsNormalized) { 'toolchain-git-admin' } else { $null }
	}
	Write-ToolchainInfo "Initialized Kubernetes cluster '$($result.Cluster)' with Toolchain registry and admission agent."
	Write-ToolchainInfo "Registry writes use credentials from secret/toolchain-registry-credentials in namespace toolchain-system."
	if ('git-server' -in $componentsNormalized) { Write-ToolchainInfo "Git administrator credentials are stored in secret/toolchain-git-admin in namespace toolchain-system." }
	if ($PassThru) { return $result }
}

function Invoke-ToolchainClusterDeinit {
	[CmdletBinding()]
	param(
		[string]$Name,
		[string]$Kubeconfig,
		[switch]$Confirm,
		[ValidateRange(10, 1800)][int]$WaitSeconds = 120,
		[switch]$PassThru
	)
	if (-not $Confirm) { throw "cluster deinit changes Kubernetes cluster state; rerun with -Confirm after reviewing 'tlc cluster deinit help'" }
	$kubeconfigPath = Resolve-ToolchainBootstrapKubeconfig -Name $Name -Kubeconfig $Kubeconfig
	$kubectl = Get-ToolchainClusterExecutable -Name kubectl -Package kubectl -InstallHint 'Install kubectl and ensure its executable is available on PATH.'
	$apiServer = Get-ToolchainBootstrapApiServer -Kubeconfig $kubeconfigPath
	$target = if ($Name) { "Toolchain cluster '$Name'" } else { 'the selected Kubernetes context' }
	try {
		$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('get', '--request-timeout=10s', '--raw=/readyz')
	} catch {
		throw "Kubernetes API preflight failed for cluster deinit at $apiServer. Confirm the provider is running and the endpoint is reachable. kubectl reported: $($_.Exception.Message)"
	}

	$removed = [Collections.ArrayList]::new()
	# Remove cluster-scoped admission/RBAC objects first so the webhook cannot
	# observe cleanup of the Toolchain namespace or any finalizers it owns.
	foreach ($resource in @('mutatingwebhookconfiguration/toolchain-agent', 'clusterrolebinding/toolchain-agent', 'clusterrole/toolchain-agent')) {
		$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('delete', $resource, '--ignore-not-found=true')
		[void]$removed.Add($resource)
	}
	$timeout = "${WaitSeconds}s"
	$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('delete', 'namespace/toolchain-system', '--ignore-not-found=true', '--wait=true', "--timeout=$timeout")
	[void]$removed.Add('namespace/toolchain-system')

	$result = [pscustomobject]@{
		PSTypeName = 'Toolchain.ClusterDeinitialization'
		Cluster = if ($Name) { $Name } else { 'current-context' }
		Kubeconfig = $kubeconfigPath
		Namespace = 'toolchain-system'
		Removed = @($removed.ToArray())
		WaitSeconds = $WaitSeconds
	}
	Write-ToolchainInfo "Removed Toolchain bootstrap resources from $($result.Cluster); the Kubernetes cluster was preserved."
	if ($PassThru) { return $result }
}

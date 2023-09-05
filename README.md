## ICMS

### 服务简介

ICMS (Infra CVE Manager Server) 是为 Opensourceways Infrastructure 开发的CVE管理服务。ICMS 的核心是使用开源安全扫描组件 trivy 扫描本地项目（从代码托管平台拉取）生成包含所有第三方包信息的 JSON 文件，将该文件中的各个包与漏洞库（Vtopia 漏洞库）匹配并保存匹配项；在所有项目的包匹配结束后，按项目维护者发送 CVE 跟踪邮件。

### 服务组件

- OPS
- trivy
- CVE Manager

### 服务流程

1. 获取所有 Infrastructure 纳管项目

	OPS 是 Infrastructure 自建的一个运维平台，也是基础设施运维的数据中心之一。目前 Infrastructure 所有纳管的项目可通过调用 OPS 提供的 API 进行查询。

- 定时刷新 OPS 平台授权 token
- 基于 OPS 平台授权 token 获取所有项目

	```
	GET https://ops.osinfra.cn/api/app_resources/repo
	Headers
		Authorization: Bearer {token}

	Response Body
		err_code
		description
		data: [
			{
				repository
				branch
				developer
				email
			},
			...
		]
	```

	示例

	```
	>>> import requests
	>>>
	>>>
	>>> url = 'https://ops.osinfra.cn/api/app_resources/repo'
	>>> headers = {'Authorization': 'Bearer ******'}
	>>> r = requests.get(url, headers=headers)
	>>> r.status_code
	200
	>>> r.json()
	{'err_code': 0, 'description': '操作成功', 'data': [{'repository': 'https://github.com/opensourceways/issue_pr_board.git', 'branch': 'main', 'developer': 'liuqi', 'email': '***@gmail.com'}, ...]}
	```

2. 扫描项目并输出项目包信息

	项目包扫描工具选择使用 trivy。[trivy](https://trivy.dev/) 是一款全面的多功能扫描器，trivy 拥有查找安全问题的扫描器，并定位可以找到这些问题的位置。trivy 可扫描的目标包括容器镜像、文件系统、Git 远程库、k8s、AWS 等。本服务中使用了 trivy 扫描本地目录的能力。
	为保证服务顺利运行，需要安装 trivy，安装步骤如下：
	-   下载 trivy 的压缩包
		`wget https://github.com/aquasecurity/trivy/releases/download/v0.42.1/trivy_0.42.1_Linux-64bit.tar.gz`
	-   解压压缩包
		`tar -zxf trivy_0.42.1_Linux-64bit.tar.gz`
		`mv ./trivy /usr/bin`
		上述命令生效后，执行 `trivy` 显示如下：

		```
		Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as
		for configuration issues and hard-coded secrets

		Usage:
		  trivy [global flags] command [flags] target
		  trivy [command]

		Examples:
		  # Scan a container image
		  $ trivy image python:3.4-alpine

		  # Scan a container image from a tar archive
		  $ trivy image --input ruby-3.1.tar

		  # Scan local filesystem
		  $ trivy fs .

		  # Run in server mode
		  $ trivy server

		Scanning Commands
		  aws         [EXPERIMENTAL] Scan AWS account
		  config      Scan config files for misconfigurations
		  filesystem  Scan local filesystem
		  image       Scan a container image
		  kubernetes  [EXPERIMENTAL] Scan kubernetes cluster
		  repository  Scan a remote repository
		  rootfs      Scan rootfs
		  sbom        Scan SBOM for vulnerabilities
		  vm          [EXPERIMENTAL] Scan a virtual machine image

		Management Commands
		  module      Manage modules
		  plugin      Manage plugins

		Utility Commands
		  completion  Generate the autocompletion script for the specified shell
		  convert     Convert Trivy JSON report into a different format
		  help        Help about any command
		  server      Server mode
		  version     Print the version

		Flags:
		      --cache-dir string          cache directory (default "/root/.cache/trivy")
		  -c, --config string             config path (default "trivy.yaml")
		  -d, --debug                     debug mode
		  -f, --format string             version format (json)
		      --generate-default-config   write the default config to trivy-default.yaml
		  -h, --help                      help for trivy
		      --insecure                  allow insecure server connections
		  -q, --quiet                     suppress progress bar and log output
		      --timeout duration          timeout (default 5m0s)
		  -v, --version                   show version

		Use "trivy [command] --help" for more information about a command.
                ```

	考虑到 `trivy repo` 命令无法扫描限制访问权限的仓库，为统一操作，将已获取的所有 Infrastructure 纳管项目同步到本地，使用 `trivy fs` 命令扫描。以项目 https://github.com/opensourceways/issue_pr_board 为例，拉取该仓库后，执行`trivy fs issue_pr_board --list-all-pkgs --format json --output issue_pr_board.json` 即可将扫描结果保存至 issue_pr_board.json，作为后续漏洞匹配的元数据。

3. 匹配漏洞

	目前漏洞匹配主要使用了来自 aqua 和 vtopia 的漏洞库。

- 匹配 aqua 漏洞

	分别读取各个项目使用 trivy 扫描生成的文件，即可匹配 aqua 漏洞。

- 匹配 vtopia 漏洞

		为与 Infrastructure 维护项目的所属社区对齐漏洞扫描方式，获取当前 Infrastructure 纳管项目的所有包，并与社区对接的漏洞库进行匹配，从而得到 Infrastructure 纳管项目存在的漏洞。

	- 获取 Infrastructure 纳管项目的包集合（字典）

		分别解析各个项目使用 trivy 扫描生成的 JSON 文件，以`包名==包版本`作为键，JSON 文件名作为值，如"uwsgi==2.0.21": ["github.com:opensourceways:mailman:main"]，最后获取的是多个这样的键值对组成的字典，记作pakcages_map后用。

	- 获取漏洞库全集

		```
		GET https://api.openeuler.org/cve-manager/v1/cve/detail/list
		Request Params
			page
			per_page
		```

		**注意：** 该请求每页最大数为 100，需翻页获取全量。

	- 匹配漏洞

		本服务暂不提供接口，漏洞匹配及后续的邮件提醒将以定时任务的方式启动。
		在匹配漏洞前取消对数据库中所有 CVE 的标记。遍历漏洞库全集，获取每条 CVE 对应的各个包的名称和版本，若`包名==包版本`是 packages_map 的一个键，则这个键对应的项目匹配这条 CVE，在数据库新建或更新一条 CVE 记录并对其标记。
		所有 CVE 匹配结束后，清除掉数据库中未标记的 CVE 记录。

4. 邮件提醒维护者修复漏洞

	获取所有需要发送提醒邮件的责任人，分别给各个责任人对应的邮箱发送提醒邮件，邮件内容包含所有涉及责任人所维护项目的 CVE 条目。

### TODOLIST

1. 添加漏洞误报上报机制

import os
import json
from attr import s
import requests
import yaml
from aws_cdk import (
    aws_ec2 as ec2,
    aws_eks as eks,
    aws_iam as iam,
    aws_certificatemanager as acm,
    aws_route53 as r53,
    core,
)
import multistack.ekselb as MyChart
import cdk8s as cdk8s
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
yamloutdir = './cdk.out/'

class eksELBHelm(core.Stack): # based on https://github.com/aws-samples/nexus-oss-on-aws/blob/d3a092d72041b65ca1c09d174818b513594d3e11/src/lib/sonatype-nexus3-stack.ts#L207-L242
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        # service account for load balancer
        self.albsvcacc = self.eksclust.add_service_account(
            "aws-load-balancer-controller",
            name="aws-load-balancer-controller",
            namespace="kube-system"
        )
        awsLBControllerVersion = 'v2.3.1' # check for new versions at https://kubernetes-sigs.github.io/aws-load-balancer-controller
        url = f"https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/{awsLBControllerVersion}/docs/install/iam_policy.json"
        mypol = requests.get(url)
        mypolstat = json.dumps(mypol.json())
        mynewpol = json.loads(mypolstat)
        for statement in mynewpol['Statement']:
            self.albsvcacc.add_to_principal_policy(iam.PolicyStatement.from_json(statement))
        # load balancer controller
        chartparam = {}
        chartparam['clusterName'] = self.eksclust.cluster_name
        chartparam['serviceAccount'] = {}
        chartparam['serviceAccount']['create'] = False
        chartparam['serviceAccount']['name'] = "aws-load-balancer-controller"
        self.manifest = eks.HelmChart(
            self,
            "Manifest-aws-load-balancer-controller",
            cluster=self.eksclust,
            chart="aws-load-balancer-controller",
            namespace="kube-system",
            repository="https://aws.github.io/eks-charts",
            values=chartparam,
            wait=True,
            create_namespace=False,
        ).node.add_dependency(self.albsvcacc)
        # # in case of failure, remove using the following cli
        # kubectl delete customresourcedefinition.apiextensions.k8s.io/targetgroupbindings.elbv2.k8s.aws
        # kubectl delete secret/aws-load-balancer-tls
        # kubectl delete clusterrole.rbac.authorization.k8s.io/aws-load-balancer-controller-role
        # kubectl delete role.rbac.authorization.k8s.io/aws-load-balancer-controller-leader-election-role
        # kubectl delete rolebinding.rbac.authorization.k8s.io/aws-load-balancer-controller-leader-election-rolebinding
        # kubectl delete service/aws-load-balancer-webhook-service
        # kubectl delete deployment.apps/aws-load-balancer-controller
        # kubectl delete mutatingwebhookconfiguration.admissionregistration.k8s.io/aws-load-balancer-webhook
        # kubectl delete validatingwebhookconfiguration.admissionregistration.k8s.io/aws-load-balancer-webhook
        # kubectl delete clusterrolebindings.rbac.authorization.k8s.io/aws-load-balancer-controller-rolebinding

class eksDNSHelm(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        # service account for external dns controller
        self.dnsvcacc = self.eksclust.add_service_account(
            "external-dns",
            name="external-dns",
            namespace=('kube-system')
        )
        # external dns controller
        self.manifest = MyChart.extdns(
            cdk8s.App(),
            "Manifest-external-dns",
            svcaccount = self.dnsvcacc,
        )
        # apply chart
        self.chart = self.eksclust.add_cdk8s_chart(
            "Chart-external-dns",
            chart=self.manifest
        ).node.add_dependency(self.dnsvcacc)


class eksELB(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        # service account for load balancer
        self.albsvcacc = self.eksclust.add_service_account(
            "aws-load-balancer-controller",
            name="aws-load-balancer-controller",
            namespace=('default')
        )
        # url = 'https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.2.0/docs/install/iam_policy.json'
        # mypol = requests.get(url)
        # mypolstat = json.dumps(mypol.json())
        # mynewpol = json.loads(mypolstat)
        # for statement in mynewpol['Statement']:
        #     self.albsvcacc.add_to_principal_policy(iam.PolicyStatement.from_json(statement))
        # load balancer controller
        self.manifest = MyChart.Albctrl(
            cdk8s.App(),
            "Manifest-aws-load-balancer-controller",
            clustername = self.eksclust.cluster_name,
            svcaccount = self.albsvcacc,
        )
        # apply chart
        self.chart = self.eksclust.add_cdk8s_chart(
            "Chart-aws-load-balancer-controller",
            chart=self.manifest
        ).node.add_dependency(self.albsvcacc)
        # # in case of failure, remove using the following cli
        # kubectl delete customresourcedefinition.apiextensions.k8s.io/targetgroupbindings.elbv2.k8s.aws
        # kubectl delete secret/aws-load-balancer-tls
        # kubectl delete clusterrole.rbac.authorization.k8s.io/aws-load-balancer-controller-role
        # kubectl delete role.rbac.authorization.k8s.io/aws-load-balancer-controller-leader-election-role
        # kubectl delete rolebinding.rbac.authorization.k8s.io/aws-load-balancer-controller-leader-election-rolebinding
        # kubectl delete service/aws-load-balancer-webhook-service
        # kubectl delete deployment.apps/aws-load-balancer-controller
        # kubectl delete mutatingwebhookconfiguration.admissionregistration.k8s.io/aws-load-balancer-webhook
        # kubectl delete validatingwebhookconfiguration.admissionregistration.k8s.io/aws-load-balancer-webhook
        # kubectl delete clusterrolebindings.rbac.authorization.k8s.io/aws-load-balancer-controller-rolebinding

class eksING(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        # service account for load balancer
        self.ingsvcacc = self.eksclust.add_service_account(
            "aws-load-balancer-controller",
            name="aws-load-balancer-controller",
            namespace=('default')
        )
        # url = 'https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.2.0/docs/install/iam_policy.json'
        # mypol = requests.get(url)
        # mypolstat = json.dumps(mypol.json())
        # mynewpol = json.loads(mypolstat)
        # for statement in mynewpol['Statement']:
        #     self.ingsvcacc.add_to_principal_policy(iam.PolicyStatement.from_json(statement))
        # load balancer controller
        self.manifest = MyChart.Ingctrl(
            cdk8s.App(),
            "Manifest-aws-load-balancer-controller",
            clustername = self.eksclust.cluster_name,
            svcaccount = self.ingsvcacc,
        )
        self.manifest = MyChart.Albctrl(
            cdk8s.App(),
            "Manifest-aws-load-balancer-controller",
            clustername = self.eksclust.cluster_name,
            svcaccount = self.albsvcacc,
        )



        # apply chart
        self.chart = eks.HelmChart(
            self,
            "Chart-aws-load-balancer-controller",
            cluster=self.eksclust,
            namespace='default',
            chart=self.manifest
        ).node.add_dependency(self.ingsvcacc)

class eksDNS(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        # service account for external dns controller
        self.dnsvcacc = self.eksclust.add_service_account(
            "external-dns",
            name="external-dns",
            namespace=('default')
        )
        # external dns controller
        self.manifest = MyChart.extdns(
            cdk8s.App(),
            "Manifest-external-dns",
            svcaccount = self.dnsvcacc,
        )
        # apply chart
        self.chart = self.eksclust.add_cdk8s_chart(
            "Chart-external-dns",
            chart=self.manifest
        ).node.add_dependency(self.dnsvcacc)

class eksNGINXHLM(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, res = str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        resconf = "resourcesmap.cfg"
        with open(resconf) as resfile:
            resmap = json.load(resfile)
        resname = resmap['Mappings']['Resources'][res]['NAME']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        elbface = resmap['Mappings']['Resources'][res]['INTERNET']
        if elbface == True:
            self.hz = r53.HostedZone.from_lookup(
                self,
                f"{construct_id}:Domain",
                domain_name=appdomain,
                private_zone=False
            )
            #generate public certificate
            self.cert = acm.Certificate(
                self,
                f"{construct_id}:Certificate",
                domain_name=f"{resname}.{appdomain}",
                validation=acm.CertificateValidation.from_dns(self.hz)
            )
        else:
            self.hz = r53.PrivateHostedZone.from_lookup(
                self,
                f"{construct_id}:PrivDomain",
                domain_name=appdomain,
                private_zone=True,
            )
        # # service account for ingress-nginx
        # self.ingnginxsvcacc = self.eksclust.add_service_account(
        #     "ingress-nginx-controller",
        #     name="ingress-nginx-controller",
        #     namespace=('default')
        # )
        # url = 'https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.1.3/docs/install/iam_policy.json'
        # mypol = requests.get(url)
        # mypolstat = json.dumps(mypol.json())
        # mynewpol = json.loads(mypolstat)
        # for statement in mynewpol['Statement']:
        #     self.ingsvcacc.add_to_principal_policy(iam.PolicyStatement.from_json(statement))
        # chart parameters
        chartparam = {}
        if "RBAC" in resmap['Mappings']['Resources'][res]:
            chartparam['rbac'] = {}
            chartparam['rbac']['create'] = resmap['Mappings']['Resources'][res]['RBAC']
        else:
            chartparam['rbac'] = {}
            chartparam['rbac']['create'] = True
        chartparam['controller'] = {}
        chartparam['controller']['name'] = 'controller'
        chartparam['controller']['containerName'] = 'controller'
        if "CONTKIND" in resmap['Mappings']['Resources'][res]:
            chartparam['controller']['kind'] = {}
            chartparam['controller']['kind'] = resmap['Mappings']['Resources'][res]['CONTKIND']
            chartparam['controller']['hostPort'] = {}
            chartparam['controller']['hostPort'] = {"enabled" : True}
        else:
            chartparam['controller']['kind'] = {}
            chartparam['controller']['kind'] = 'DaemonSet'
            chartparam['controller']['hostPort'] = {}
            chartparam['controller']['hostPort'] = {"enabled" : True}
        chartparam['controller']['hostNetwork'] = True
        chartparam['controller']['config'] = {}
        chartparam['controller']['config']['proxy-body-size'] = "512m"
        if "SVC" in resmap['Mappings']['Resources'][res]:
            chartparam['controller']['service'] = {}
            chartparam['controller']['service'] = resmap['Mappings']['Resources'][res]['SVC']
        else:
            chartparam['controller']['service'] = {}
            chartparam['controller']['service'] = {
                "enabled" : True,
                "externalTrafficPolicy": "Local",
                "type": "LoadBalancer"
            }
        if "ANNOT" in resmap['Mappings']['Resources'][res]:
            chartparam['controller']['service']['annotations'] = {}
            chartparam['controller']['service']['annotations'] = resmap['Mappings']['Resources'][res]['ANNOT']
        else:
            chartparam['controller']['service']['annotations'] = {}
            chartparam['controller']['service']['annotations'] = {
                "service.beta.kubernetes.io/aws-load-balancer-proxy-protocol" : "*",
                "service.beta.kubernetes.io/aws-load-balancer-backend-protocol" : "http",
                "service.beta.kubernetes.io/aws-load-balancer-ssl-ports": "https",
                "service.beta.kubernetes.io/aws-load-balancer-ssl-cert" : self.cert.certificate_arn,
                "external-dns.alpha.kubernetes.io/hostname" : f"{resname}.{appdomain}",
                "external-dns.alpha.kubernetes.io/ttl" : 60
            }
        chartparam['controller']['service']['name'] = 'ingress-nginx'
        chartparam['serviceAccount'] = {}
        chartparam['serviceAccount']['create'] = True
        # add chart controller

        self.chart = eks.HelmChart(
            self,
            "ingress-nginx",
            chart="ingress-nginx",
            cluster=self.eksclust,
            namespace="default",
            release='nginx',
            repository="https://kubernetes.github.io/ingress-nginx",
            values=chartparam,
            wait=True,
            create_namespace=True,
        )

class eksNGINXMNF(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, res = str, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.eksclust = ekscluster
        resconf = "resourcesmap.cfg"
        with open(resconf) as resfile:
            resmap = json.load(resfile)
        resname = resmap['Mappings']['Resources'][res]['NAME']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        elbface = resmap['Mappings']['Resources'][res]['INTERNET']
        if elbface == True:
            self.hz = r53.HostedZone.from_lookup(
                self,
                f"{construct_id}:Domain",
                domain_name=appdomain,
                private_zone=False
            )
            #generate public certificate
            self.cert = acm.Certificate(
                self,
                f"{construct_id}:Certificate",
                domain_name=f"{resname}.{appdomain}",
                validation=acm.CertificateValidation.from_dns(self.hz)
            )
        else:
            self.hz = r53.PrivateHostedZone.from_lookup(
                self,
                f"{construct_id}:PrivDomain",
                domain_name=appdomain,
                private_zone=True,
            )
        if elbface == True:
            url = 'https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v0.47.0/deploy/static/provider/aws/deploy-tls-termination.yaml'
        else:
            url = 'https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v0.47.0/deploy/static/provider/aws/deploy.yaml'
        mnftlst = yaml.load_all(requests.get(url).content, Loader=yaml.FullLoader)
        manifest = []
        for item in mnftlst:
            if "CONTKIND" in resmap['Mappings']['Resources'][res]:
                if resmap['Mappings']['Resources'][res]["CONTKIND"] != 'Deployment':
                    if item['kind'] == 'Deployment':
                        item['kind'] = 'DaemonSet'
            if elbface == True:
                if 'data' in item:
                    if item['data']['proxy-real-ip-cidr'] == 'XXX.XXX.XXX/XX':
                        item['data']['proxy-real-ip-cidr'] = self.vpc.vpc_cidr_block
                if item['kind'] == 'Service':
                    if 'annotations' in item['metadata']:
                        if 'service.beta.kubernetes.io/aws-load-balancer-ssl-cert' in item['metadata']['annotations']:
                            if item['metadata']['annotations']['service.beta.kubernetes.io/aws-load-balancer-ssl-cert'] == 'arn:aws:acm:us-west-2:XXXXXXXX:certificate/XXXXXX-XXXXXXX-XXXXXXX-XXXXXXXX':
                                item['metadata']['annotations']['service.beta.kubernetes.io/aws-load-balancer-ssl-cert'] = self.cert.certificate_arn
                                item['metadata']['annotations']['external-dns.alpha.kubernetes.io/hostname'] = f"{resname}.{appdomain}"
                                item['metadata']['annotations']['external-dns.alpha.kubernetes.io/ttl'] = '60'
                                item['metadata']['annotations']['service.kubernetes.io/local-svc-only-bind-node-with-pod'] = 'true'
            manifest.append(item)
        #manifest = yaml.dump_all(mnftlst)
        self.Manifest = eks.KubernetesManifest(
            self,
            'nginx-ingress-controller',
            cluster=self.eksclust,
            manifest=manifest,
            overwrite=True,
            skip_validation=True
        )
        #write manifest yaml file
        yamlmanifest = yaml.dump_all(manifest)
        outputyaml = f"{yamloutdir}{construct_id}.yaml"
        outputfile = open(outputyaml, 'w')
        outputfile.write(yamlmanifest)
        outputfile.close()
        
class eksINGMNF(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        # service account for load balancer
        self.ingsvcacc = eks.ServiceAccount(
            self,
            "aws-load-balancer-controller-service-account",
            name="aws-load-balancer-controller",
            namespace=('default'),
            cluster=self.eksclust
        )
        url = 'https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.2.0/docs/install/iam_policy.json'
        mypol = requests.get(url)
        mypolstat = json.dumps(mypol.json())
        mynewpol = json.loads(mypolstat)
        for statement in mynewpol['Statement']:
            self.ingsvcacc.add_to_principal_policy(iam.PolicyStatement.from_json(statement))
        # load balancer controller
        url = 'https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.2.0/docs/install/v2_2_0_full.yaml'
        mnftlst = yaml.load_all(requests.get(url).content, Loader=yaml.FullLoader)
        manifest = []
        for item in mnftlst:
            if item['kind'] == 'Deployment':
                if 'containers' in item['spec']['template']['spec']:
                    for container in item['spec']['template']['spec']['containers']:
                        if 'args' in container:
                            for arg in container['args']:
                                if arg == "--cluster-name=your-cluster-name":
                                    arg = "--cluster-name={{ cluster-name }}"
            manifest.append(item)
        #manifest = yaml.dump_all(mnftlst)
        self.Manifest = eks.KubernetesManifest(
            self,
            'aws-load-balancer-controller',
            cluster=self.eksclust,
            manifest=manifest,
            overwrite=True,
            skip_validation=True
        )
        #write manifest yaml file
        yamlmanifest = yaml.dump_all(manifest)
        outputyaml = f"{yamloutdir}{construct_id}.yaml"
        outputfile = open(outputyaml, 'w')
        outputfile.write(yamlmanifest)
        outputfile.close()

class eksinsights(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        # based on https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-logs-FluentBit.html
        # create namespace
        url = 'https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/cloudwatch-namespace.yaml'
        mnftlst = yaml.load_all(requests.get(url).content, Loader=yaml.FullLoader)
        manifest = []
        for item in mnftlst:
            manifest.append(item)
        self.Manifestns = eks.KubernetesManifest(
            self,
            f"Manifest-cloudwatch-Namespace",
            cluster=self.eksclust,
            manifest=manifest,
            overwrite=True,
            skip_validation=True
        )
        # service account for container insights
        self.eksclust = ekscluster
        self.insightssvcacc = eks.ServiceAccount(
            self,
            "cloudwatch-agent-service-account",
            name="fluent-bit",
            namespace=("amazon-cloudwatch"),
            cluster=self.eksclust,
        )
        self.insightssvcacc.role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchAgentServerPolicy"))
        self.insightssvcacc.node.add_dependency(self.Manifestns)
        # cloudmap account for fluent-bit-cluster-info
        manifest = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { 
                "name": "fluent-bit-cluster-info",
                "namespace": "amazon-cloudwatch"
            },
            "data": { 
                "cluster.name": self.eksclust.cluster_name,
                "logs.region": region,
                "http.server": "On",
                "http.port": "2020",
                "read.head": "Off",
                "read.tail": "On",
            }
        }
        self.Manifestcfmflt = eks.KubernetesManifest(
            self,
            f"Manifest-Configmap-fluent-bit",
            cluster=self.eksclust,
            manifest=[manifest],
            overwrite=True,
            skip_validation=True
            )
        self.Manifestcfmflt.node.add_dependency(self.Manifestns)
        # install fluent-bit optimized configuration
        url = 'https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/fluent-bit/fluent-bit.yaml'
        mnftlst = yaml.load_all(requests.get(url).content, Loader=yaml.FullLoader)
        manifest = []
        for item in mnftlst:
            if item['kind'] != 'ServiceAccount':
                manifest.append(item)
        self.Manifestflt = eks.KubernetesManifest(
            self,
            f"Manifest-fluent-bit",
            cluster=self.eksclust,
            manifest=manifest,
            overwrite=True,
            skip_validation=True
        )
        self.Manifestflt.node.add_dependency(self.Manifestcfmflt)

        # url = 'https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/quickstart/cwagent-fluent-bit-quickstart.yaml'
        # lines=requests.get(url).text
        # lines=lines.replace('{{cluster_name}}', self.eksclust.cluster_name)
        # lines=lines.replace('{{region_name}}', region)
        # lines=lines.replace('{{http_server_toggle}}', 'On')
        # lines=lines.replace('{{http_server_port}}', '2020')
        # lines=lines.replace('{{read_from_head}}', 'Off')
        # lines=lines.replace('{{read_from_tail}}', 'On')
        # mnftlst = yaml.load_all(lines, Loader=yaml.FullLoader)
        # manifest = []
        # count = 1
        # for item in mnftlst:
        #     manifest.append(item)
        #     if item['kind'] == 'Namespace':
        #         self.Manifestns = eks.KubernetesManifest(
        #             self,
        #             f"Manifest-Configmap-fluent-bit",
        #             cluster=self.eksclust,
        #             manifest=[item],
        #             overwrite=True,
        #             skip_validation=True
        #         )
        #         # service account for load balancer
        #         self.insightssvcacc = eks.ServiceAccount(
        #             self,
        #             "cloudwatch-agent-service-account",
        #             name="cloudwatch-agent",
        #             namespace=('amazon-cloudwatch'),
        #             cluster=self.eksclust,
        #         )
        #         self.insightssvcacc.role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name('CloudWatchAgentServerPolicy'))
        #         self.insightssvcacc.node.add_dependency(self.Manifestns)
        #         count = count + 1
        #     # else:
        #     #     eks.KubernetesManifest(
        #     #         self,
        #     #         f"Manifest-cloudwatch-{itemkind}-{count}",
        #     #         cluster=self.eksclust,
        #     #         manifest=[item],
        #     #         overwrite=True,
        #     #         skip_validation=True
        #     #     ).node.add_dependency(self.insightssvcacc)
        #     #     count = count + 1
        # #write manifest yaml file
        # yamlmanifest = yaml.dump_all(manifest)
        # outputyaml = f"{yamloutdir}{construct_id}cwagent-serviceaccount.yaml"
        # outputfile = open(outputyaml, 'w')
        # outputfile.write(yamlmanifest)
        # outputfile.close()
class eksinsightshelm(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        # service account for fluent-bit
        self.fluentbitsvcacc = self.eksclust.add_service_account(
            "fluent-bit",
            name="fluent-bit",
            namespace=('amazon-cloudwatch')
        )
        self.fluentbitsvcacc.role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name('CloudWatchAgentServerPolicy'))
        # Install controller via Helm
        self.chart = eks.HelmChart(
            self,
            "Chart-aws-for-fluent-bit",
            cluster=self.eksclust,
            namespace='amazon-cloudwatch',
            chart='aws-for-fluent-bit',
            release='aws-for-fluent-bit',
            values={
                "serviceAccount": {
                    "create": False,
                    "name": "fluent-bit"
                },
                "cloudWatch": {
                    "awsRegion": self.region,
                },
                "firehose": {
                    "enabled": False
                },
                "kinesis": {
                    "enabled": False
                },
                "elasticsearch": {
                    "enabled": False
                }
            }
        ).node.add_dependency(self.fluentbitsvcacc)

class ekscwinsights(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        # based on https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-EKS-quickstart.html
        # create namespace
        manifest = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { 
                "name": "amazon-cloudwatch",
                "labels" : {
                    "name": "amazon-cloudwatch"
                }
            }
        }
        self.Manifestns = eks.KubernetesManifest(
            self,
            f"Manifest-cloudwatch-Namespace",
            cluster=self.eksclust,
            manifest=[manifest],
            overwrite=True,
            skip_validation=True
        )
        # service account for cwagent service
        self.cwagentsvcacc = eks.ServiceAccount(
            self,
            "cwagent-service-account",
            name="cloudwatch-agent",
            namespace=("amazon-cloudwatch"),
            cluster=self.eksclust,
        )
        self.cwagentsvcacc.role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchAgentServerPolicy"))
        self.cwagentsvcacc.node.add_dependency(self.Manifestns)
        # service account for fluent-bit
        self.fluentbitsvcacc = eks.ServiceAccount(
            self,
            "fluent-bit-service-account",
            name="fluent-bit",
            namespace=("amazon-cloudwatch"),
            cluster=self.eksclust,
        )
        self.fluentbitsvcacc.role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchAgentServerPolicy"))
        self.fluentbitsvcacc.node.add_dependency(self.Manifestns)
        # install Quick Start setup for Container Insights
        url = 'https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/quickstart/cwagent-fluent-bit-quickstart.yaml'
        lines=requests.get(url).text
        lines=lines.replace("{{cluster_name}}", self.eksclust.cluster_name)
        lines=lines.replace("{{region_name}}", region)
        lines=lines.replace("{{http_server_toggle}}", '\"On\"')
        lines=lines.replace("{{http_server_port}}", '\"2020\"')
        lines=lines.replace("{{read_from_head}}", '\"Off\"')
        lines=lines.replace("{{read_from_tail}}", '\"On\"')
        mnftlst = yaml.load_all(lines, Loader=yaml.FullLoader)
        manifest = []
        for item in mnftlst:
            if item['kind'] == 'ServiceAccount':
                next
            elif item['kind'] == 'Namespace':
                next
            else:
                manifest.append(item)
        self.Manifestflt = eks.KubernetesManifest(
            self,
            f"Manifest-container-insights",
            cluster=self.eksclust,
            manifest=manifest,
            overwrite=True,
            skip_validation=True
        )
        self.Manifestflt.node.add_dependency(self.Manifestflt)
        #write manifest yaml file
        yamlmanifest = yaml.dump_all(manifest)
        outputyaml = f"{yamloutdir}{construct_id}cwagent-serviceaccount.yaml"
        outputfile = open(outputyaml, 'w')
        outputfile.write(yamlmanifest)
        outputfile.close()


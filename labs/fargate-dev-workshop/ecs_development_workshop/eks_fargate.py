# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: MIT-0
from aws_cdk.aws_iam import Role
from aws_cdk.core import PhysicalName
from ecs_development_workshop.code_pipeline_configuration import ContainerPipelineConfiguration

from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_ecr as ecr,
    aws_eks as eks,
    aws_logs as logs,
    core
)

import json
from django.http import JsonResponse


class EksFargate(core.Stack):

    def __init__(self, scope: core.Construct, id: str, config: ContainerPipelineConfiguration, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # VPC
        vpc = ec2.Vpc(scope=self, id="EksVPC",
                      cidr="12.0.0.0/16",
                      nat_gateways=1,
                      )

        master_role = iam.Role(self, 'cluster-master-role',
                               assumed_by=iam.AccountRootPrincipal(),
                               )

        # EKS on Fargate cluster
        cluster = eks.FargateCluster(scope=self, id='EksOnFargate',
                                     vpc=vpc,
                                     masters_role=master_role,
                                     version=eks.KubernetesVersion.V1_19,
                                     output_config_command=True,
                                     output_cluster_name=True,
                                     output_masters_role_arn=True,
                                     endpoint_access=eks.EndpointAccess.PUBLIC_AND_PRIVATE,
                                     )
        # EKS with managed nodes
        # cluster = eks.Cluster(scope=self, id='EksManagedNodes',
        #                       vpc=vpc,
        #                       masters_role=master_role,
        #                       version=eks.KubernetesVersion.V1_19,
        #                       output_config_command=True,
        #                       output_cluster_name=True,
        #                       output_masters_role_arn=True,
        #                       default_capacity=3,
        #                       default_capacity_instance=ec2.InstanceType.of(
        #                           ec2.InstanceClass.STANDARD5,
        #                           ec2.InstanceSize.LARGE
        #                       ),
        #                       endpoint_access=eks.EndpointAccess.PUBLIC_AND_PRIVATE,
        #                       )

        cluster.node.add_dependency(vpc)

        # EKS master IAM roles
        # cloud9_master_role = iam.Role.from_role_arn(self, "Cloud9-fargate-role",
        #                                             role_arn=f"arn:aws:iam::{self.account}:role/Cloud9-fargate-role")
        # cluster.aws_auth.add_masters_role(cloud9_master_role)

        # grant access to final CodeBuild stage projects to do kubectl apply
        # eks_master_role_for_codedeploy: Role = iam.Role(
        #     self, "EksMasterRoleForCodeDeploy",
        #     role_name=PhysicalName.GENERATE_IF_NEEDED,
        #     assumed_by=iam.ServicePrincipal('codebuild.amazonaws.com'),
        # )
        #
        # codedeploy_role_policy_statement = iam.PolicyStatement(
        #     actions=["eks:DescribeFargateProfile",
        #              "eks:ListTagsForResource",
        #              "eks:AccessKubernetesApi",
        #              "eks:DescribeCluster"],
        #     resources=["*"]
        # )
        # eks_master_role_for_codedeploy.add_to_policy(codedeploy_role_policy_statement)
        # cluster.aws_auth.add_masters_role(eks_master_role_for_codedeploy)

        # setup logs
        log_group = logs.LogGroup(
            self, "log_group",
            log_group_name=config.ProjectName + "-eks-" + config.stage,
            removal_policy=core.RemovalPolicy.DESTROY,
            retention=None
        )
        log_group.add_stream(config.ProjectName + "-" + config.stage + "-eks-stream")

        # Create an K8S Service Account for AWS Load Balancer Controller on EKS cluster.
        # @aws_cdk/aws_eks module will also automatically create the corresponding IAM Role mapped via IRSA
        aws_lb_controller_service_account = cluster.add_service_account(
            "aws-load-balancer-controller",
            namespace="kube-system",
        )

        lb_acm_policy_statements = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                'acm:DescribeCertificate',
                'acm:ListCertificates',
                'acm:GetCertificate',
            ],
            resources=['*'],
        )

        lb_ec2_policy_statements = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                'ec2:AuthorizeSecurityGroupIngress',
                'ec2:CreateSecurityGroup',
                'ec2:CreateTags',
                'ec2:DeleteTags',
                'ec2:DeleteSecurityGroup',
                'ec2:DescribeAccountAttributes',
                'ec2:DescribeAddresses',
                'ec2:DescribeInstances',
                'ec2:DescribeInstanceStatus',
                'ec2:DescribeInternetGateways',
                'ec2:DescribeNetworkInterfaces',
                'ec2:DescribeSecurityGroups',
                'ec2:DescribeSubnets',
                'ec2:DescribeTags',
                'ec2:DescribeVpcs',
                'ec2:ModifyInstanceAttribute',
                'ec2:ModifyNetworkInterfaceAttribute',
                'ec2:RevokeSecurityGroupIngress',
            ],
            resources=['*'],
        )
        lb_elb_policy_statements = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                'elasticloadbalancing:AddListenerCertificates',
                'elasticloadbalancing:AddTags',
                'elasticloadbalancing:CreateListener',
                'elasticloadbalancing:CreateLoadBalancer',
                'elasticloadbalancing:CreateRule',
                'elasticloadbalancing:CreateTargetGroup',
                'elasticloadbalancing:DeleteListener',
                'elasticloadbalancing:DeleteLoadBalancer',
                'elasticloadbalancing:DeleteRule',
                'elasticloadbalancing:DeleteTargetGroup',
                'elasticloadbalancing:DeregisterTargets',
                'elasticloadbalancing:DescribeListenerCertificates',
                'elasticloadbalancing:DescribeListeners',
                'elasticloadbalancing:DescribeLoadBalancers',
                'elasticloadbalancing:DescribeLoadBalancerAttributes',
                'elasticloadbalancing:DescribeRules',
                'elasticloadbalancing:DescribeSSLPolicies',
                'elasticloadbalancing:DescribeTags',
                'elasticloadbalancing:DescribeTargetGroups',
                'elasticloadbalancing:DescribeTargetGroupAttributes',
                'elasticloadbalancing:DescribeTargetHealth',
                'elasticloadbalancing:ModifyListener',
                'elasticloadbalancing:ModifyLoadBalancerAttributes',
                'elasticloadbalancing:ModifyRule',
                'elasticloadbalancing:ModifyTargetGroup',
                'elasticloadbalancing:ModifyTargetGroupAttributes',
                'elasticloadbalancing:RegisterTargets',
                'elasticloadbalancing:RemoveListenerCertificates',
                'elasticloadbalancing:RemoveTags',
                'elasticloadbalancing:SetIpAddressType',
                'elasticloadbalancing:SetSecurityGroups',
                'elasticloadbalancing:SetSubnets',
                'elasticloadbalancing:SetWebAcl',
            ],
            resources=['*'],
        )

        lb_iam_policy_statements = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                'iam:CreateServiceLinkedRole',
                'iam:GetServerCertificate',
                'iam:ListServerCertificates',
            ],
            resources=['*'],
        )

        lb_cognito_policy_statements = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=['cognito-idp:DescribeUserPoolClient'],
            resources=['*'],
        )

        lb_waf_reg_policy_statements = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                'waf-regional:GetWebACLForResource',
                'waf-regional:GetWebACL',
                'waf-regional:AssociateWebACL',
                'waf-regional:DisassociateWebACL',
            ],
            resources=['*'],
        )

        lb_tag_policy_statements = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=['tag:GetResources', 'tag:TagResources'],
            resources=['*'],
        )

        lb_waf_policy_statements = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=['waf:GetWebACL'],
            resources=['*'],
        )

        lb_wafv2_policy_statements = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                'wafv2:GetWebACL',
                'wafv2:GetWebACLForResource',
                'wafv2:AssociateWebACL',
                'wafv2:DisassociateWebACL',
            ],
            resources=['*'],
        )

        lb_shield_policy_statements = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                'shield:DescribeProtection',
                'shield:GetSubscriptionState',
                'shield:DeleteProtection',
                'shield:CreateProtection',
                'shield:DescribeSubscription',
                'shield:ListProtections',
            ],
            resources=['*'],
        )
        #
        aws_lb_controller_service_account.add_to_policy(lb_acm_policy_statements)
        aws_lb_controller_service_account.add_to_policy(lb_ec2_policy_statements)
        aws_lb_controller_service_account.add_to_policy(lb_elb_policy_statements)
        aws_lb_controller_service_account.add_to_policy(lb_iam_policy_statements)
        aws_lb_controller_service_account.add_to_policy(lb_cognito_policy_statements)
        aws_lb_controller_service_account.add_to_policy(lb_waf_reg_policy_statements)
        aws_lb_controller_service_account.add_to_policy(lb_tag_policy_statements)
        aws_lb_controller_service_account.add_to_policy(lb_waf_policy_statements)
        aws_lb_controller_service_account.add_to_policy(lb_wafv2_policy_statements)
        aws_lb_controller_service_account.add_to_policy(lb_shield_policy_statements)

        # Deploy AWS LoadBalancer Controller from the Helm chart
        lb_helm_values = dict(cluster_name=cluster.cluster_name, region=self.region, vpc_id=cluster.vpc.vpc_id,
                              create_service_account=False)

        helm_deploy = cluster.add_helm_chart('aws-load-balancer-controller',
                                             chart="aws-load-balancer-controller",
                                             repository="https://aws.github.io/eks-charts",
                                             namespace="kube-system",
                                             values=lb_helm_values,
                                             )
        helm_deploy.node.add_dependency(cluster)

        # service account
        # k8s_app_namespace = 'default'
        # k8s_app_service_account = 'sa-fargate-apps'
        # conditions = core.CfnJson(self, 'RoleConditionJson',
        #                           value={
        #                               f"{cluster.cluster_open_id_connect_issuer}:aud": (
        #                                   "sts.amazonaws.com"
        #                               ),
        #                               f"{cluster.cluster_open_id_connect_issuer}:sub": (
        #                                   f"system:serviceaccount:${k8s_app_namespace}:${k8s_app_service_account}"
        #                               ),
        #                           },
        #                           )
        # iam_federated_principal = iam.FederatedPrincipal(
        #     cluster.open_id_connect_provider.open_id_connect_provider_arn,
        #     conditions=conditions,
        #     assume_role_action="sts:AssumeRoleWithWebIdentity"
        # )
        # iam_role_for_k8s_sa = iam.Role(self, "fargate-apps-sa-role",
        #                                assumed_by=iam_federated_principal,
        #                                )

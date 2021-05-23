# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: MIT-0

from ecs_development_workshop.code_pipeline_configuration import ContainerPipelineConfiguration
from aws_cdk import (
    aws_codebuild,
    aws_iam as iam,
    aws_codecommit,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as codepipeline_actions,
    aws_ecr as ecr,
    core,
)


class DockerBuildToEcrPipeline(core.Stack):

    def __init__(self, scope: core.Construct, id: str, config: ContainerPipelineConfiguration, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # sourceOutput = codepipeline.Artifact(
        #     artifact_name=config.ProjectName + "-SourceOutput"
        # )

        # Code Repo
        commit = aws_codecommit.Repository(
            self,
            config.ProjectName + "-apprepo",
            repository_name=config.ProjectName + "-app-repo"
        )

        # Container Repo
        self.docker_repo = ecr.Repository(
            scope=self,
            id=config.ProjectName,
            removal_policy=core.RemovalPolicy.DESTROY,
            repository_name=config.ProjectName
        )

        pipeline = codepipeline.Pipeline(self, "MyPipeline",
                                         pipeline_name=config.ProjectName + "-commit-to-ecr"
                                         )

        source_output = codepipeline.Artifact()

        source_action = codepipeline_actions.CodeCommitSourceAction(
            action_name="CodeCommit",
            repository=commit,
            output=source_output
        )

        # docker file linting
        cb_docker_build_lint = aws_codebuild.PipelineProject(
            self, "DockerLint",
            project_name=config.ProjectName + "-docker-lint",
            build_spec=aws_codebuild.BuildSpec.from_source_filename(
                filename='configs/buildspec_lint.yml'),
            environment=aws_codebuild.BuildEnvironment(
                build_image=aws_codebuild.LinuxBuildImage.UBUNTU_14_04_NODEJS_10_1_0,
                privileged=True,
            ),
            # pass the ecr repo uri into the codebuild project so codebuild knows where to push
            environment_variables={
                'ecr': aws_codebuild.BuildEnvironmentVariable(
                    value=self.docker_repo.repository_uri),
                'project_name': aws_codebuild.BuildEnvironmentVariable(
                    value=config.ProjectName)
            },
            description='linting the container dockerfile for best practices',
            timeout=core.Duration.minutes(60),
        )

        # code repo secret scan
        cb_source_secretscan = aws_codebuild.PipelineProject(
            self, "SourceSecretScan",
            project_name=config.ProjectName + "-source-secretscan",
            build_spec=aws_codebuild.BuildSpec.from_source_filename(
                filename='configs/buildspec_secrets.yml'),
            environment=aws_codebuild.BuildEnvironment(
                privileged=True,
                build_image=aws_codebuild.LinuxBuildImage.AMAZON_LINUX_2_3,
            ),
            # pass the ecr repo uri into the codebuild project so codebuild knows where to push
            environment_variables={
                'commituri': aws_codebuild.BuildEnvironmentVariable(
                    value=commit.repository_clone_url_http),
                'ecr': aws_codebuild.BuildEnvironmentVariable(
                    value=self.docker_repo.repository_uri),
                'project_name': aws_codebuild.BuildEnvironmentVariable(
                    value=config.ProjectName)
            },
            description='Scanning source for secrets',
            timeout=core.Duration.minutes(60),
        )

        cb_source_secretscan.add_to_role_policy(
            statement=iam.PolicyStatement(
                resources=['*'],
                actions=['codecommit:*']
            )
        )

        # push to ecr repo
        # cb_docker_build_push = aws_codebuild.PipelineProject(
        #     self, "DockerBuild",
        #     project_name= config.ProjectName + "-docker-build",
        #     build_spec=aws_codebuild.BuildSpec.from_source_filename(
        #         filename='configs/docker_build_base.yml'),
        #     environment=aws_codebuild.BuildEnvironment(
        #         privileged=True,
        #         compute_type=aws_codebuild.ComputeType.MEDIUM
        #     ),
        #     # pass the ecr repo uri into the codebuild project so codebuild knows where to push
        #     environment_variables={
        #         'ecr': aws_codebuild.BuildEnvironmentVariable(
        #             value=self.docker_repo.repository_uri),
        #         'tag': aws_codebuild.BuildEnvironmentVariable(
        #             value="release"),
        #         'project_name': aws_codebuild.BuildEnvironmentVariable(
        #             value=config.ProjectName)
        #     },
        #     description='Deploy to ECR',
        #     timeout=core.Duration.minutes(60),
        # )

        # push Spring app to ecr repo and deploy
        cb_spring_build_deploy = aws_codebuild.PipelineProject(
            self, "SpringBuildDeploy",
            project_name=config.ProjectName + "-spring-build-deploy",
            build_spec=aws_codebuild.BuildSpec.from_source_filename(
                filename='configs/spring_build_deploy.yml'),
            environment=aws_codebuild.BuildEnvironment(
                privileged=True,
                build_image=aws_codebuild.LinuxBuildImage.AMAZON_LINUX_2_3,
                compute_type=aws_codebuild.ComputeType.MEDIUM
            ),
            # pass the ecr repo uri into the codebuild project so codebuild knows where to push
            environment_variables={
                'ecr': aws_codebuild.BuildEnvironmentVariable(
                    value=self.docker_repo.repository_uri),
                'tag': aws_codebuild.BuildEnvironmentVariable(
                    value="release"),
                'project_name': aws_codebuild.BuildEnvironmentVariable(
                    value=config.ProjectName)
            },
            description='Deploy to ECR and Push to Fargate',
            timeout=core.Duration.minutes(60),
        )

        # grant access to all CodeBuild projects to pull images from ECR
        statement = iam.PolicyStatement(
            actions=["ecr:GetAuthorizationToken",
                     "ecr:BatchCheckLayerAvailability",
                     "ecr:GetDownloadUrlForLayer",
                     "ecr:BatchGetImage",
                     "ecr:DescribeRepositories",
                     "ecr:DescribeImages",
                     "ecr:ListImages",
                     ],
            resources=['*']
        )

        # cb_docker_build_push.add_to_role_policy(statement)
        cb_spring_build_deploy.add_to_role_policy(statement)
        cb_docker_build_lint.add_to_role_policy(statement)
        cb_source_secretscan.add_to_role_policy(statement)

        pipeline.add_stage(
            stage_name="Source",
            actions=[source_action]
        )

        pipeline.add_stage(
            stage_name='Lint',
            actions=[
                codepipeline_actions.CodeBuildAction(
                    action_name='DockerLintImages',
                    input=source_output,
                    project=cb_docker_build_lint,
                    run_order=1,
                )
            ]
        )

        pipeline.add_stage(
            stage_name='SecretScan',
            actions=[
                codepipeline_actions.CodeBuildAction(
                    action_name='SourceSecretScanImages',
                    input=source_output,
                    project=cb_source_secretscan,
                    run_order=1,
                )
            ]
        )

        pipeline.add_stage(
            # stage_name='Build',
            stage_name='BuildAndDeploy',
            actions=[
                codepipeline_actions.CodeBuildAction(
                    # action_name='DockerBuildImages',
                    action_name='SpringBuildAndDeploy',
                    input=source_output,
                    # project= cb_docker_build_push,
                    project=cb_spring_build_deploy,
                    run_order=1,
                )
            ]
        )

        # self.docker_repo.grant_pull_push(cb_docker_build_push)
        self.docker_repo.grant_pull_push(cb_spring_build_deploy)


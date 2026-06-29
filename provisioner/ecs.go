package main

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

type ECSClient struct {
	client *ecs.Client
	cfg    *Config
}

func NewECSClient(cfg *Config) (*ECSClient, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(cfg.AWSRegion),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %w", err)
	}
	return &ECSClient{
		client: ecs.NewFromConfig(awsCfg),
		cfg:    cfg,
	}, nil
}

func (e *ECSClient) RunTask(username string) (string, error) {
	tags := []ecstypes.Tag{
		{Key: aws.String("traefik.enable"), Value: aws.String("true")},
		{Key: aws.String("username"), Value: aws.String(username)},
	}

	input := &ecs.RunTaskInput{
		Cluster:        aws.String(e.cfg.ECSCluster),
		TaskDefinition: aws.String(e.cfg.TaskDefinitionARN),
		LaunchType:     ecstypes.LaunchTypeFargate,
		Count:          aws.Int32(1),
		NetworkConfiguration: &ecstypes.NetworkConfiguration{
			AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{
				Subnets:        e.cfg.SubnetIDs,
				SecurityGroups: []string{e.cfg.SecurityGroupID},
				AssignPublicIp: ecstypes.AssignPublicIpEnabled,
			},
		},
		Tags: tags,
	}

	output, err := e.client.RunTask(context.Background(), input)
	if err != nil {
		return "", fmt.Errorf("failed to run task: %w", err)
	}

	if len(output.Tasks) == 0 {
		if len(output.Failures) > 0 {
			return "", fmt.Errorf("task failed: %s - %s",
				aws.ToString(output.Failures[0].Arn),
				aws.ToString(output.Failures[0].Reason))
		}
		return "", fmt.Errorf("no tasks launched")
	}

	return aws.ToString(output.Tasks[0].TaskArn), nil
}

func (e *ECSClient) StopTask(taskArn string) error {
	_, err := e.client.StopTask(context.Background(), &ecs.StopTaskInput{
		Cluster: aws.String(e.cfg.ECSCluster),
		Task:    aws.String(taskArn),
		Reason:  aws.String("stopped by provisioner"),
	})
	return err
}

func (e *ECSClient) ListTasks() ([]string, error) {
	output, err := e.client.ListTasks(context.Background(), &ecs.ListTasksInput{
		Cluster: aws.String(e.cfg.ECSCluster),
	})
	if err != nil {
		return nil, err
	}
	return output.TaskArns, nil
}

func (e *ECSClient) DescribeTask(taskArn string) (*ecstypes.Task, error) {
	output, err := e.client.DescribeTasks(context.Background(), &ecs.DescribeTasksInput{
		Cluster: aws.String(e.cfg.ECSCluster),
		Tasks:   []string{taskArn},
	})
	if err != nil {
		return nil, err
	}
	if len(output.Tasks) == 0 {
		return nil, fmt.Errorf("task not found: %s", taskArn)
	}
	return &output.Tasks[0], nil
}

func (e *ECSClient) WaitForRunning(taskArn string) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		task, err := e.DescribeTask(taskArn)
		if err != nil {
			return err
		}
		if task.LastStatus != nil && *task.LastStatus == "RUNNING" {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for task %s to reach RUNNING state", taskArn)
}

// GetTaskIP returns the private IPv4 address of the first container's
// first network interface for an awsvpc (Fargate) task. Used to route
// per-user subdomains to the user's task.
func (e *ECSClient) GetTaskIP(taskArn string) (string, error) {
	task, err := e.DescribeTask(taskArn)
	if err != nil {
		return "", err
	}
	if len(task.Containers) == 0 {
		return "", fmt.Errorf("task %s has no containers", taskArn)
	}
	nis := task.Containers[0].NetworkInterfaces
	if len(nis) == 0 || aws.ToString(nis[0].PrivateIpv4Address) == "" {
		return "", fmt.Errorf("task %s container has no network interface IP", taskArn)
	}
	return aws.ToString(nis[0].PrivateIpv4Address), nil
}

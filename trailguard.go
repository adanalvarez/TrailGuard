package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/awalterschulze/gographviz"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/s3"
)

func printTable(dict map[string]string) {
	var maxKeyLen int
	var maxValueLen int
	for key, value := range dict {
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
		}
		if len(value) > maxValueLen {
			maxValueLen = len(value)
		}
	}

	fmt.Printf(" %s\n", strings.Repeat("-", maxKeyLen+maxValueLen+5))
	fmt.Printf("| %-*s | %-*s |\n", maxKeyLen, "Command", maxValueLen, "Description")
	fmt.Printf(" %s\n", strings.Repeat("-", maxKeyLen+maxValueLen+5))
	for key, value := range dict {
		fmt.Printf("| %-*s | %-*s |\n", maxKeyLen, key, maxValueLen, value)
	}
	fmt.Printf(" %s\n", strings.Repeat("-", maxKeyLen+maxValueLen+5))
}

func lambdaRisks() {
	dict := make(map[string]string)
	dict["delete-*"] = "Delete the lambda or important parts of it."
	dict["remove-*"] = "Revoke function-use permission or remove a statement from the permissions policy for a version of an Lambda layer "
	dict["update-*"] = "Change the current code or configurations."
	dict["put-*"] = "Add extra configurations such as currency."
	fmt.Printf("      -  Risks of some Lambda commands  -  \n")
	printTable(dict)
}

func snsRisks() {
	dict := make(map[string]string)
	dict["delete-*"] = "Delete the SNS or important parts of it."
	dict["remove-permission"] = "Removes a statement from a topic's access control policy."
	dict["publish-*"] = "Send a message/s to an Amazon SNS topic"
	dict["put-data-protection-policy"] = "Add or update an inline policy document that is stored in the specified Amazon SNS topic."
	dict["unsubscribe"] = "Delete a subscription."
	dict["subscribe"] = "Subscribe an endpoint to an Amazon SNS topic."
	dict["set-*"] = "Configuration changes that might affect the SNS."
	fmt.Printf("      -  Risks of some SNS commands  -  \n")
	printTable(dict)
}

func sqsRisks() {
	dict := make(map[string]string)
	dict["add-permission"] = "Add a permission to a queue for a specific principal."
	dict["change-*"] = "Change the visibility timeout of a message/s in a queue to a new value."
	dict["delete-*"] = "Delete messages from the queue or the queue."
	dict["purge-queue"] = "Delete messages from the queue."
	dict["receive-message"] = "Retrieve one or more messages."
	dict["remove-permission"] = "Revoke any permissions in the queue policy that matches the specified Label parameter."
	dict["send-message"] = "Delivers a message to the specified queue."
	dict["set-queue-attributes"] = "Sets the value of one or more queue attributes."
	fmt.Printf("      -  Risks of some SQS commands  -  \n")
	printTable(dict)
}

func kinesisFirehoseRisks() {
	dict := make(map[string]string)
	dict["delete-delivery-stream"] = "Delete a delivery stream and its data."
	dict["put-*"] = "Writes data into an Amazon Kinesis Data Firehose delivery stream."
	dict["start-delivery-stream-encryption"] = "Enable server-side encryption (SSE) for the delivery stream.."
	dict["stop-delivery-stream-encryption"] = "Disable server-side encryption (SSE) for the delivery stream."
	dict["update-destination"] = "Update the specified destination of the specified delivery stream."
	fmt.Printf("      -  Risks of some Kinesis Firehose commands  -  \n")
	printTable(dict)
}

func kinesisRisks() {
	dict := make(map[string]string)
	dict["decrease-stream-retention-period"] = "Decrease the Kinesis data stream's retention period, which is the length of time data records are accessible after they are added to the stream."
	dict["delete-stream"] = "Delete a Kinesis data stream and all its shards and data"
	dict["deregister-stream-consumer"] = "Deregister a consumer"
	dict["put-*"] = "Put data record/s into an Amazon Kinesis data stream"
	dict["register-stream-consumer"] = "Register a consumer with a Kinesis data stream"
	dict["start-stream-encryption"] = "Enable or update server-side encryption using an Amazon Web Services KMS key for a specified stream"
	dict["stop-stream-encryption"] = "Disable server-side encryption for a specified stream"
	dict["update-*"] = "Update to the stream configuration"
	fmt.Printf("      -  Risks of some Kinesis commands  -  \n")
	printTable(dict)
}

func opensearchServiceRisks() {
	dict := make(map[string]string)
	dict["accept-inbound-connection"] = "Allows the destination Amazon OpenSearch Service domain owner to accept an inbound cross-cluster search connection request."
	dict["*-package"] = "Associate or dissociate a package from the Amazon OpenSearch Service domain."
	dict["delete-"] = "Delete the domain or important configurations"
	dict["reject-inbound-connection"] = "Reject an inbound cross-cluster connection request."
	dict["revoke-vpc-endpoint-access"] = "Revoke access to an Amazon OpenSearch Service domain that was provided through an interface VPC endpoint"
	dict["update-*"] = "Update to the OpenSearch configuration"
	fmt.Printf("      -  Risks of some OpenSearch commands  -  \n")
	printTable(dict)
}

func s3Risks() {
	dict := make(map[string]string)
	dict["delete-*"] = "Delete the bucket, it's configuration or the files"
	dict["put-*"] = "Change configurations or add new objects"
	dict["copy-object"] = "Create a copy of an object that is already stored in Amazon S3."
	dict["create-multipart-upload"] = "Initiate a multipart upload"
	fmt.Printf("      -  Risks of some S3 commands  -  \n")
	printTable(dict)
}

func cloudWatchRisks() {
	dict := make(map[string]string)
	dict["delete-*"] = "Delete the loggroup, logs or it's configurations"
	dict["put-*"] = "Change configurations or add new logs"
	dict["create-export-task"] = "Create an export task so that you can efficiently export data from a log group to an Amazon S3 bucket."
	dict["associate-kms-key"] = "Associate the specified KMS key with the specified log group."
	dict["disassociate-kms-key"] = "Disassociate the associated KMS key from the specified log group."
	fmt.Printf("      -  Risks of some CloudWatch Log Group commands  -  \n")
	printTable(dict)
}

func checkCloudWatchSubscriptionFilters(sess *session.Session, logGroupARN string, g *gographviz.Graph, servicesSlice *[]string) {
	parts := strings.Split(logGroupARN, ":")
	logGroupName := parts[6]

	svc := cloudwatchlogs.New(sess)

	input := &cloudwatchlogs.DescribeSubscriptionFiltersInput{
		LogGroupName: aws.String(logGroupName),
	}

	result, err := svc.DescribeSubscriptionFilters(input)
	if err != nil {
		panic(err)
	}

	if len(result.SubscriptionFilters) != 0 {
		for _, filter := range result.SubscriptionFilters {
			g.AddNode("\""+logGroupARN+"\"", "\""+*filter.DestinationArn+"\"", nil)
			g.AddEdge("\""+logGroupARN+"\"", "\""+*filter.DestinationArn+"\"", true, nil)
			if strings.Contains(*filter.DestinationArn, "lambda") {
				fmt.Println("    - Lambda ARN:", *filter.DestinationArn)
				*servicesSlice = append(*servicesSlice, "Lambda")
			}
			if strings.Contains(*filter.DestinationArn, "kinesis") {
				fmt.Println("    - Kinesis ARN:", *filter.DestinationArn)
				*servicesSlice = append(*servicesSlice, "Kinesis")
			}
			if strings.Contains(*filter.DestinationArn, "firehose") {
				fmt.Println("    - Firehose ARN:", *filter.DestinationArn)
				*servicesSlice = append(*servicesSlice, "Firehose")
			}
			if strings.Contains(*filter.DestinationArn, "domain") {
				fmt.Println("    - OpenSearch ARN:", *filter.DestinationArn)
				*servicesSlice = append(*servicesSlice, "OpenSearch")
			}

		}
	}
}

func checkBucketNotifications(sess *session.Session, bucketName string, g *gographviz.Graph, servicesSlice *[]string) {
	svc := s3.New(sess)

	result, err := svc.GetBucketNotificationConfiguration(&s3.GetBucketNotificationConfigurationRequest{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		panic(err)
	}
	if len(result.LambdaFunctionConfigurations) != 0 {
		for _, config := range result.LambdaFunctionConfigurations {
			fmt.Println("    - Lambda ARN:", *config.LambdaFunctionArn)
			g.AddNode("\""+bucketName+"\"", "\""+*config.LambdaFunctionArn+"\"", nil)
			g.AddEdge("\""+bucketName+"\"", "\""+*config.LambdaFunctionArn+"\"", true, nil)
		}
		*servicesSlice = append(*servicesSlice, "Lambda")
	}
	if len(result.QueueConfigurations) != 0 {
		for _, config := range result.QueueConfigurations {
			fmt.Println("    - SQS ARN:", *config.QueueArn)
			g.AddNode("\""+bucketName+"\"", "\""+*config.QueueArn+"\"", nil)
			g.AddEdge("\""+bucketName+"\"", "\""+*config.QueueArn+"\"", true, nil)
		}
		*servicesSlice = append(*servicesSlice, "SQS")
	}
	if len(result.TopicConfigurations) != 0 {
		for _, config := range result.TopicConfigurations {
			fmt.Println("    - SNS ARN:", *config.TopicArn)
			g.AddNode("\""+bucketName+"\"", "\""+*config.TopicArn+"\"", nil)
			g.AddEdge("\""+bucketName+"\"", "\""+*config.TopicArn+"\"", true, nil)
		}
		*servicesSlice = append(*servicesSlice, "SNS")
	}
}

func main() {
	servicesSlice := make([]string, 0)
	sess, err := session.NewSession()

	svc := cloudtrail.New(sess)
	result, err := svc.DescribeTrails(nil)
	if err != nil {
		panic(err)
	}
	g := gographviz.NewGraph()
	for _, trail := range result.TrailList {
		g.SetName("Test")
		g.SetDir(true)
		g.AddNode("\""+*trail.Name+"\"", "\""+*trail.Name+"\"", nil)
		fmt.Println("\nTRAIL NAME:", *trail.Name)
		if trail.CloudWatchLogsLogGroupArn != nil {
			servicesSlice = append(servicesSlice, "CloudWatchLogsLogGroup")
			g.AddNode("\""+*trail.Name+"\"", "\""+*trail.CloudWatchLogsLogGroupArn+"\"", nil)
			g.AddEdge("\""+*trail.Name+"\"", "\""+*trail.CloudWatchLogsLogGroupArn+"\"", true, nil)
			fmt.Println("  - CloudWatch log group ARN:", *trail.CloudWatchLogsLogGroupArn)
			//cloudWatchRisks()
			checkCloudWatchSubscriptionFilters(sess, *trail.CloudWatchLogsLogGroupArn, g, &servicesSlice)
		}
		if trail.S3BucketName != nil {
			servicesSlice = append(servicesSlice, "S3")
			g.AddNode("\""+*trail.Name+"\"", "\""+*trail.S3BucketName+"\"", nil)
			g.AddEdge("\""+*trail.Name+"\"", "\""+*trail.S3BucketName+"\"", true, nil)
			fmt.Println("  - Bucket Name:", *trail.S3BucketName)
			//s3Risks()
			checkBucketNotifications(sess, *trail.S3BucketName, g, &servicesSlice)
		}
		err := ioutil.WriteFile("cloudtrail.dot", []byte(g.String()), 0644)
		if err != nil {
			log.Fatalf("Error rendering graph: %v", err)
		}
	}

	fmt.Println("\n----------\n")
	fmt.Println("Possible risks associated with the services used: ")
	if strings.Contains(strings.Join(servicesSlice, ""), "S3") {
		lambdaRisks()
	}
	if strings.Contains(strings.Join(servicesSlice, ""), "CloudWatchLogsLogGroup") {
		cloudWatchRisks()
	}
	if strings.Contains(strings.Join(servicesSlice, ""), "SNS") {
		snsRisks()
	}
	if strings.Contains(strings.Join(servicesSlice, ""), "SQS") {
		sqsRisks()
	}
	if strings.Contains(strings.Join(servicesSlice, ""), "Lambda") {
		lambdaRisks()
	}
	if strings.Contains(strings.Join(servicesSlice, ""), "OpenSearch") {
		opensearchServiceRisks()
	}
	if strings.Contains(strings.Join(servicesSlice, ""), "Firehose") {
		kinesisFirehoseRisks()
	}
	if strings.Contains(strings.Join(servicesSlice, ""), "Kinesis") {
		kinesisRisks()
	}

}

# AWSTrailGuard
Tool to check the CloudTrail configuration and the services where trails are sent, to detect potential attacks to CloudTrail logging.

## Introduction

CloudTrail is a valuable service provided by AWS that enables the logging and tracking of API calls in the AWS platform. It is crucial for security and compliance purposes. However, it's essential to ensure that CloudTrail configuration is set up correctly to avoid logging interruptions and maintain the logs' integrity. But the security of CloudTrail does not stop only with the CloudTrail setup.

Because Cloudtrail configuration usually is well monitored, any attempt to stop logging, delete trail, or update won't be allowed and might trigger a security alert. Adversaries might try to disturb the logs by attacking other services that, in many configurations, are equally important, such as the s3 bucket or the lambda that is enabled to parse the records from the s3 (if it exists).

AWSTrailGuard provides a simple and efficient way to get better visibility of the services where the logs are being sent, checking if logs are sent to S3 and CloudWatch and if the S3 has any Bucket notifications or if Cloudwatch has any Subscription filters. The tool prints the information on the console and generates a DOT file with the diagram. The DOT file can be used to create a png.

```dot -T png cloudtrail.dot > cloudtrail.png```

## Example

Console output:

![ConsoleOutput](consoleoutput.png)

Graph visualization:

![GraphVisualization](graphvisualization.png)

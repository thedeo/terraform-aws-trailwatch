# TrailWatch - AWS Organization Monitor

### What is TrailWatch?
TrailWatch is an open source monitoring solution for AWS Organizations. Deployment with Terraform makes it easy for anyone to implement and tear down.

The dashboard web interface uses Django along with the DataTables library to produce dynamic data views. 

The dashboard provides 4 built in reports:

1. **account**
2. **ami**
3. **securitygroup**
4. **user**

These reports provide the ability to filter and search resources across the entire organization from one user interface. Reports run every hour by default but this can be customized through a Terraform variable.

By default an hourly event summary email will be sent to email addresses of your choice. The email doesn't include specifics but instead just enough for you to understand what is happening in your AWS accounts. This helps engineers get visibility without being spammed with too much detail. If you need to dig further into an event, a link to the dashboard will take you just to the set of events from that time period.

Code deployments are handled by native CI/CD tools. Terraform will update a zip file in s3. AWS EventBridge will detect this and kick off a pipeline execution.

### What does it solve?
TrailWatch is all about visibility into your entire organization at the control plane. The idea is to provide clean, customizable alerts and dashboards for easy consumption of control plane events across your entire AWS Organization.

### Who is it for?
TrailWatch is designed to scale with your organization which makes it a great low cost choice for small to medium sized environments. You can deploy in a larger environment but just be aware it has not been fully tested in large environments.

### How much will it cost?
The cost drivers are going to be the ECS containers, ALB and Lambda invocations. You shouldn't expect the cost to be more than about $25-50/month. This may vary depending on the size of your environment. But as always be sure to track your spend.


## Screenshots
![1](https://github.com/thedeo/trailwatch/raw/master/images/1.png)
![2](https://github.com/thedeo/trailwatch/raw/master/images/2.png)
![3](https://github.com/thedeo/trailwatch/raw/master/images/3.png)
![4](https://github.com/thedeo/trailwatch/raw/master/images/4_2.png)

## Prerequisites
Due to the nature of this solution, there are some manual prerequisites. These are typically things that you will have already done unless you're starting with a fresh AWS account/organization. As of this project's creation there are no APIs avilable to automate *some* of these configurations. Some of these are left manual due to the likelihood you may have already configured them for other projects.

1. **Enable AWS Organizations on your "management account".**
2. **Enable CloudFormation StackSets service in Organizations.**
3. **Enable SCP policy type in Organizations.**
4. **Manual modification of AWSCloudFormationStackSetExecutionRole.**
	If you already have this role in your management account you will need to ensure
	that it has permissions defined in org_resources/iam_roles.tf
5. **Create SES identity/domain to be used to send event summary emails.**
6. **Create Route53 domain to be used for the dashboard web interface.**
7. **Create ACM certificate associated with the Route53 domain.**
	Example: `dashboard.example.com`

## Installation
Terraform variables are used to name resources and identify existing resources that are required for the solution.

| Variable    | Detail                                                                                           |
| :---------------------------- | :------------------------------------ |
| **project_name**  			| Used for naming throughout the project. **Default:** TrailWatch |
| **region**  					| This solution is designed to only run in the **us-east-1** AWS region. The reason for this is because that is where all of the AWS global events are logged. You might be able to customize the solution to run in another region but it might not function as expected.  |
| **profile** 					| You will need to make sure to reference the profile you have configured in either ~/.aws/credentials or ~/.aws/config.  **Default:** default |
| **trusted_cidrs** 				| This LIST will be used to allow access via Security Group to the dashboard web interface. Make sure to set this to a trusted network. |
| **dashboard_domain** 			| **Hosted Zone ID** for the dashboard. An Alias for `dashboard.example.com` will be created and pointed at the ALB. |
| **alb_tls_cert_arn** 			| ARN of the manually created ACM certificate that for the dashboard domain. The certificate will need to be for **`dashboard.YOURDOMAIN.com`**.    |
| **dockerhub_username** 		| Required for the CodeBuild project to sign in. This avoids the DockerHub rate limit.|
| **dockerhub_password** 		| See above. |
| **dashboard_report_frequency**| How often (minutes) to run the built in reports [account, ami, securitygroup, user]. **Default:** 60min |
| **ses_identity_arn** 			| ARN of the manually created SES identity/domain that will be used to send email alerts. This domain should match the **alert_sender** email domain.  |
| **email_summary_frequency** 	| Specify the frequency in minutes for how often event summaries will be sent. **Default:** 60 |
| **alert_sender** 				| Email address that SES will use to send alerts. Ensure that it matches the domain associated with **ses_identity_arn**. Example: `alerts@example.com` |
| **alert_recipients** 			| List of email addresses that alerts will be sent to. You may receive a subscription invitation from SNS for Lambda Error monitors. Example: `["noc@example.com","other@example.com"]`  |
| **ignored_iam_principals** 	| List of users/roles. This can be used to ignore certain AWS IAM users or roles in the email summary logic. You need only to include the unique name of the IAM principal. Example: `["myusername","PoptartRole"]` |
| **create_cf_stackset_roles** 	| If you already have created the AWS roles AWSCloudFormationStackSetAdministrationRole & AWSCloudFormationStackSetExecutionRole then you should set this to *false*. **Default:** true |

Once you've set all the variables you can simply run the typical Terraform deployment commands.
`$ terraform init`
`$ terraform validate`
`$ terraform apply`

You will notice that the **org_cf_stacks.tf** and **member_cf_stacks.tf** take some time to run. The reason is that Terraform runs each CloudFormation StackSet Instance one at a time. Both of these StackSets are necessary in order to ensure that any new accounts added to your Organization get the EventBridge rules needed to be monitored.


# Security Considerations

None of the information processed or stored by this solution would be considered particularly sensitive. However, I recommend that when deploying the solution you limit network access to the dashboard only to trusted networks. Make sure you update the Terraform variable named **trusted_cidrs**.

The dashboard has functionality to support ADFS SAML authentication but since this is just a POC that functionality is disabled by default in Django. The **django-auth-adfs** libraries are commented out. If you want to use the built in Django admin console you will need to uncomment the path for 'admin/' in urls.py. If you decide to enable the admin URI, you can hit the admin by just typing in **/admin/** to the end of your domain. Make sure to include the trailing slash.

#### Django Admin Default Password
| Username | Password      |
|----------|---------------|
| admin    | Zombiepaper47$|


# Customizations

The EventPatterns configured in **org_resources/variables.tf** can be customized to your liking. You may find them to be too verbose or maybe not verbose enough. If you change them in that file, they will be updated across the entire solution. Just remember that updates to the StackSets can take a long time so be sure to **give it some thought before updating** .

As you can imagine, since everything is written in Terraform you can customize the solution from any aspect you like.

# Troubleshooting

If you get a **503 Service Temporarily Unavailable** after the Terraform finishes, just check the CodePipeline in the AWS console and give it a few minutes. The ECS deployment can take a few moments to complete.

import json
import boto3
import bcrypt
import time
from botocore.exceptions import ClientError
import jwt
import json
from datetime import datetime, timezone, timedelta

# Initialize SNS client
sns_client = boto3.client('sns', region_name='eu-west-1')

# Initialize DynamoDB resource
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('users')  # Use your Users table name
tasks_table = dynamodb.Table('tasks')  # Use your Tasks table name

# Secret key for signing JWT tokens
SECRET_KEY = "g0Jf9d&3KLp1X7m@qTz5#A9wV%Nv^2HQWcE$r6J*bFZ8XsY"


# cors headers
cors_headers = {
    "Access-Control-Allow-Origin": "*",  # Adjust based on allowed origins
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",  # Allowed methods
    "Access-Control-Allow-Headers": "Content-Type, Authorization",  # Allowed headers
}

# User Registration Lambda
def user_registration_handler(event, context):
    try:
        # Extract user data from event body
        body = json.loads(event['body'])
        email = body['email']
        password = body['password']
        role = body['role']
        firstname = body['firstname']

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        #hashed_password = password
        # Generate unique user_id
        user_id = "user_" + str(int(time.time()))  # Use current timestamp to generate user_id
        
        # Store user in DynamoDB
        users_table.put_item(
            Item={
                'user_id': user_id,
                'email': email,
                'password': hashed_password,
                'role': role,
                'firstname': firstname,
                'created_at': str(time.time())
            }
        )
        
        return {
            'statusCode': 201,
            'headers': cors_headers,
            'body': json.dumps({'message': 'User created successfully', 'user_id': user_id})
        }

    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }

# Get User Details Lambda
def get_user_details_handler(event, context):
    try:
        user_id = event['pathParameters']['user_id']  # Assuming user_id is passed in the path

        # Fetch user from DynamoDB
        response = users_table.get_item(Key={'user_id': user_id})

        if 'Item' in response:
            user_details = response['Item']
            if 'password' in user_details:
                del user_details['password']
            return {
                'statusCode': 200,
                'headers': cors_headers,
                'body': json.dumps(user_details)
            }
        else:
            return {
                'statusCode': 404,
                'headers': cors_headers,
                'body': json.dumps({'message': 'User not found'})
            }

    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }

# Get all users
def get_all_users_handler(event, context):
    try:
        # Scan the Users table
        response = users_table.scan()
        for user in response['Items']:
            if 'password' in user:
                del user['password']

        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({'users': response['Items']})
        }
    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }

# Generate a JWT token
def generate_token(user_id, email):
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": time.time() + 3600  # Token expires in 1 hour
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

# User Login Lambda
def user_login_handler(event, context):
    try:
        # Extract login details from event
        body = json.loads(event['body'])
        email = body['email']
        password = body['password']

        # Query DynamoDB for user by email
        response = users_table.scan(
            FilterExpression="email = :email",
            ExpressionAttributeValues={":email": email}
        )

        if response['Items']:
            user = response['Items'][0]  # Assuming email is unique
            stored_password = user['password']

            # Check if entered password matches stored password
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
            #if password == stored_password:  # Replace with bcrypt if needed
                # Generate JWT token
                token = generate_token(user['user_id'], email)

                if 'password' in user:
                    del user['password']

                return {
                    'statusCode': 200,
                    'headers': cors_headers,
                    'body': json.dumps({
                        'message': 'Login successful',
                        'user': user,
                        'access_token': token
                    })
                }
            else:
                return {
                    'statusCode': 400,
                    'headers': cors_headers,
                    'body': json.dumps({'message': 'Invalid password'})
                }
        else:
            return {
                'statusCode': 404,
                'headers': cors_headers,
                'body': json.dumps({'message': 'User not found'})
            }

    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }

# Create Task Lambda
def create_task_handler(event, context):
    try:
        # Extract task details from the event body
        body = json.loads(event['body'])
        task_id = "task_" + str(int(time.time()))  # Use current timestamp to generate task_id
        assigned_to = body['assigned_to']
        status = body['status']
        deadline = body['deadline']
        description = body['description']
        title = body['title']
        
        # Store task in DynamoDB
        tasks_table.put_item(
            Item={
                'task_id': task_id,
                'title': title,
                'assigned_to': assigned_to,
                'status': status,
                'deadline': deadline,
                'description': description,
                'created_at': datetime.now(timezone.utc).isoformat()
            }
        )

        # Prepare the full task response
        task = {
            'task_id': task_id,
            'title': title,
            'assigned_to': assigned_to,
            'status': status,
            'deadline': deadline,
            'description': description,
            'created_at': datetime.now(timezone.utc).isoformat()
        }

        return {
            'statusCode': 201,
            'headers': cors_headers,
            'body': json.dumps({
                'message': 'Task created successfully',
                'task': task
            })
        }

    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }

# Get Tasks by User Lambda
def get_tasks_by_user_handler(event, context):
    try:
        user_id = event['pathParameters']['user_id']  # Assuming user_id is passed in the path

        # Query tasks table to fetch tasks assigned to the user
        response = tasks_table.scan(
            FilterExpression="assigned_to = :user_id",
            ExpressionAttributeValues={":user_id": user_id}
        )

        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({'tasks': response['Items']})
        }

    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }

# Get all tasks
def get_all_tasks_handler(event, context):
    try:
        # Scan the Tasks table
        response = tasks_table.scan()
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({'tasks': response['Items']})
        }
    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }

# Get specific task
def get_single_task_handler(event, context):
    try:
        task_id = event['pathParameters']['task_id']  # Assuming task_id is passed in the path

        # Get the task from the Tasks table
        response = tasks_table.get_item(Key={'task_id': task_id})

        if 'Item' in response:
            return {
                'statusCode': 200,
                'headers': cors_headers,
                'body': json.dumps(response['Item'])
            }
        else:
            return {
                'statusCode': 404,
                'headers': cors_headers,
                'body': json.dumps({'message': 'Task not found'})
            }
    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }

# Update Task Lambda
def update_task_handler(event, context):
    try:
        # Parse the request body
        body = json.loads(event['body'])
        # Extract task_id from pathParameters
        task_id = event['pathParameters']['task_id']
        updated_attributes = {}
        expression_attribute_names = {}
        expression_attribute_values = {}

        # Map allowed fields for update
        allowed_fields = ['title', 'description', 'assigned_to', 'status', 'deadline']

        for field in allowed_fields:
            if field in body:
                updated_attributes[f"#{field}"] = body[field]
                expression_attribute_names[f"#{field}"] = field
                expression_attribute_values[f":{field}"] = body[field]

        # Ensure there are fields to update
        if not updated_attributes:
            return {
                'statusCode': 400,
                'headers': cors_headers,
                'body': json.dumps({'message': 'No valid fields to update'})
            }

        # Construct the update expression
        update_expression = "set " + ", ".join(
            [f"{key} = {value}" for key, value in zip(expression_attribute_names.keys(), expression_attribute_values.keys())]
        )

        # Update task in DynamoDB
        tasks_table.update_item(
            Key={'task_id': task_id},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
        )

        # Fetch the updated task data from DynamoDB
        response = tasks_table.get_item(
            Key={'task_id': task_id}
        )

        # Check if the task exists after the update
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'headers': cors_headers,
                'body': json.dumps({'message': 'Task not found'})
            }

        # Return the full updated task
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({'message': 'Task updated successfully', 'task': response['Item']})
        }

    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }

# Update Task Status Lambda
def update_task_status_handler(event, context):
    try:
        body = json.loads(event['body'])
        task_id = body['task_id']
        new_status = body['status']

        # Update task in DynamoDB
        response = tasks_table.update_item(
            Key={'task_id': task_id},
            UpdateExpression="set #st = :status",
            ExpressionAttributeNames={'#st': 'status'},
            ExpressionAttributeValues={':status': new_status},
            ReturnValues="UPDATED_NEW"
        )

        # Fetch the updated task from DynamoDB
        response = tasks_table.get_item(Key={'task_id': task_id})

        # Check if the task exists
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'headers': cors_headers,
                'body': json.dumps({'message': 'Task not found'})
            }

        # Get the full updated task item
        updated_task = response['Item']

        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({
                'message': 'Task updated successfully',
                'task': updated_task  # Return the full updated task
            })
        }

    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }

# Delete Task Lambda
def delete_task_handler(event, context):
    try:
        task_id = event['pathParameters']['task_id']  # Assuming task_id is passed in the path

        # Delete task from DynamoDB
        tasks_table.delete_item(Key={'task_id': task_id})

        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({'message': 'Task deleted successfully'})
        }

    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'message': str(e)})
        }


# Notifications handler
def send_sns_notification(topic_arn, subject, message):
    try:
        response = sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        print(f"Notification sent: {response['MessageId']}")
        return response
    except Exception as e:
        print(f"Failed to send notification: {str(e)}")
        raise


def deadline_monitor_handler(event, context):
    try:
        # Fetch all tasks from DynamoDB
        response = tasks_table.scan()
        tasks = response['Items']
        now = datetime.now(timezone.utc)

        # Check for tasks nearing their deadline
        for task in tasks:
            deadline = datetime.fromisoformat(task['deadline'])
            time_left = deadline - now

            # Send notification if deadline is within 24 hours
            if timedelta(hours=0) < time_left <= timedelta(hours=24):
                message = (
                    f"Task '{task['title']}' is approaching its deadline. "
                    f"Deadline: {task['deadline']}"
                )
                send_sns_notification(
                    topic_arn="arn:aws:sns:eu-west-1:124355665480:TaskDeadlineNotification",
                    subject="Task Deadline Approaching",
                    message=message
                )
    except Exception as e:
        print(f"Error in monitoring deadlines: {str(e)}")
        raise

# REST-API-message-system

The messaging system is a simple rest API system responsible for handling messages between users.

# Features
1. Write a Message - a user can write a message that will save in the database.
2. Get all Messages from a specific user - The app gets all the messages that a specific user has sent or received.
3. Get all unread messages from a specific user - The app gets all the unread messages that a specific user has sent. or has received it.
4. read a specific Message - This brings a specific message by id number. (user can only see his messages after login)
5. Delete Message - The app enables to delete the specific message. (user can only see his messages after login)

# Accessing the App

User can access the app from any browser or any API tool 
I'll use Postman for demonstration purpose

# Hosting

The app hosted at https://auth-rest-api-app.herokuapp.com/

# Using the app:

First, you'll have to create a USER :

Use Post method on this endpoint:https://auth-rest-api-app.herokuapp.com/user

at the header section set Content-Type as the key
                          application/json as the value 

at the body section use "raw" and JSON

``` swift
{
    "name": "some_name",
    "password": "some_password",
    
}
```



Log in:

Use GET method on this endpoint:https://auth-rest-api-app.herokuapp.com/login
in the Authorization set the type for Basic Auth
and fill the user name and password fields of the user you created

optional existing users you can log in with:

Anna - Anna_password
Bill - Bill_password
Corey - Corey_passsword

copy the token You got without the ""

Header section:
set the Key to x-access-token
        Value <paste the Token>
    
the Token is valid for 30 min!!!

writing a message - use POST method on this endpoint: https://auth-rest-api-app.herokuapp.com/msg

user should declare in the header 
Content-Type: application/json

user should provide 3 parameters in the body (receiver, subject, body) in JSON format.

``` swift
{"receiver": "Spiderman",
"subject": "message for Spider",
"body": "If you spell Chuck Norris in Scrabble, you win. Forever."}
```



Get all unread messages of the logged-in user (as a sender or as reciver) -  use GET method on this endpoint: https://auth-rest-api-app.herokuapp.com/msg/unread

Note if you'll do it 2 times in a raw the second request will return an empty response becasue the first request has "read" the messages.

Get all messages of the logged-in user (as a sender or as a receiver) -  use GET method on this endpoint: https://auth-rest-api-app.herokuapp.com/msg/all


  
Read a specific message -  use GET method on this endpoint: https://auth-rest-api-app.herokuapp.com/msg/id
        
The user should declare the message-id number he would like to read.
  
  
 Delete message - use DELETE method on this endpoint: https://auth-rest-api-app.herokuapp.com/msg/id
The user should declare the message-id he wishes to delete.
  
  
# Message Content
the message contains the following parameters :

- [x] ID
- [x] Sender
- [x] Receiver
- [x] Subject
- [x] Body
- [x] Date Posted
- [x] Boolean parameter if the message was read:
 True stand for the message has been read False stands for the message has not read
 
 Get all users:
 
 use GET method on this endpoint: https://auth-rest-api-app.herokuapp.com/user
 Note no need to be logged in for this request 
 
.

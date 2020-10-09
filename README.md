# REST-API-message-system

The messaging system is a simple rest API system responsible for handling messages between users.

# Features
1. Write a Message - a user can write a message that will save in the database.
2. Get all Messages from a specific user - The app gets all the messages that a specific user has sent.
3. Get all unread messages from a specific user - The app gets all the unread messages that a specific user has sent.
4. read a specific Message - This brings a specific message by id number.
5. Delete Message - The app enables to delete the specific message.

# Accessing the App

User can access the app from any browser or an API tool 

# Hosting

The app hosted at https://my-app-dan.herokuapp.com/

# Using the app:

writing a message - use POST method on this endpoint: https://my-app-dan.herokuapp.com/message

user should declare in the header 
Content-Type: application/json

user must provide 4 parameters in the body (sender, receiver, subject, body) in JSON format.

``` swift
{
    "sender": "some_sender",
    "receiver": "some_receiver",
    "subject": "some_subject",
    "body": "some_message_body"

}
```
Get all messages or all unread messages from a specific user -  use GET method on this endpoint: https://my-app-dan.herokuapp.com/message/<sender>/<all/unread>
  
The user should declare in the second parameter if he would like to get "unread" messages from a specific sender or "all"  the messages of that specific user.
  
Read a specific message -  use GET method on this endpoint: https://my-app-dan.herokuapp.com/message/<id>
The user should declare the message-id number he would like to read.
  
 Delete message - use DELETE method on this endpoint: https://my-app-dan.herokuapp.com/message/<id>
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
.

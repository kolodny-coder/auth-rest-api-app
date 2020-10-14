import unittest

import requests
from requests.auth import HTTPBasicAuth

import api

base_url = 'https://auth-rest-api-app.herokuapp.com/'


class TestApi(unittest.TestCase):
    def test_welcome_page(self):
        self.assertEqual(api.welcome_page(), '<h1>Welcome To Messaging System</h1>')

    def test_get_all_users(self):

        response = requests.get(url=base_url + '/user')
        data = response.json()  # extracting data in json format
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(data)

    def test_create_user(self):
        data = {'name': 'some_name', 'password': 'some_password'}
        response = requests.post(url=base_url + '/user', json=data)
        self.assertEqual(response.json(), {"message": "New user created!"})
        self.assertEqual(response.status_code, 200)


    def test_login(self):
        with self.subTest('login fails due to user name dosen"t exist'):
            response = requests.get(url=base_url + '/login', auth=HTTPBasicAuth('non_existing_name',
                                                                                'some_password'))
            self.assertEqual(response.text, 'Could not verify')
            self.assertEqual(response.status_code, 401)

        with self.subTest('login raises failed due to auth was given'):
            response = requests.get(url=base_url + '/login')
            self.assertEqual(response.headers['WWW-Authenticate'], 'Basic realm="Login required!"')

        with self.subTest('login fails due to wrong password'):
            response = requests.get(url=base_url + '/login', auth=HTTPBasicAuth('some_name', 'wrong_password'))
            self.assertEqual(response.text, 'Could not verify')
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.headers['WWW-Authenticate'], 'Basic realm="Login required!"')

        with self.subTest('login generate token successfully'):
            response = requests.get(url=base_url + '/login', auth=HTTPBasicAuth('some_name', 'some_password'))
            self.assertEqual(response.status_code, 200)
            self.assertIsInstance(response.json()['token'], str)


    def test_create_msg(self):
        response = requests.get(url=base_url + '/login', auth=HTTPBasicAuth('some_name', 'some_password'))
        headers = {'x-access-token': response.json()['token']}
        data = {'receiver': 'receiver_1', 'subject': 'subject_no_1', 'body': 'the message content'}
        response = requests.post(url=base_url + '/msg', headers=headers, json=data)
        self.assertEqual(response.json(), {'message': 'Message created!'})
        self.assertEqual(response.status_code, 200, )


    def test_get_all_messages(self):

        response = requests.get(url=base_url + '/login', auth=HTTPBasicAuth('some_name', 'some_password'))
        headers = {'x-access-token': response.json()['token']}

        with self.subTest('get all messages read & unread'):
            response = requests.get(url=base_url + '/msg/all', headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertIsInstance(response.json(), dict)

            for msg in response.json()['messages']:
                self.assertEqual(msg['sender'], 'some_name')

        with self.subTest('get only unread messages'):
            data_1 = {'receiver': 'receiver_1', 'subject': 'unread_message_test_no_1',
                      'body': 'the message content_no_1'}
            requests.post(url=base_url + '/msg', headers=headers, json=data_1)

            response = requests.get(url=base_url + '/msg/unread', headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertIsInstance(response.json(), dict)

            for msg in response.json()['messages']:
                self.assertEqual(msg['is_message_read'], False)

    def test_get_one_msg(self):
        # Creating new message
        response = requests.get(url=base_url + '/login', auth=HTTPBasicAuth('some_name', 'some_password'))
        headers = {'x-access-token': response.json()['token']}
        data_1_msg_test = {'receiver': '1_msg_receiver', 'subject': 'lets test get 1 msg',
                           'body': 'the message content 1 msg test'}
        requests.post(url=base_url + '/msg', headers=headers, json=data_1_msg_test)

        # Getting the last created message id
        response = requests.get(url=base_url + '/msg/all', headers=headers)
        msg_id = 0
        for msg in response.json()['messages']:
            if msg['id'] > msg_id:
                msg_id = msg['id']

        # Getting the last created message
        response = requests.get(url=base_url + '/msg/' + str(msg_id), headers=headers)
        self.assertIsInstance(response.json(), dict)
        self.assertEqual(response.status_code, 200)

    def test_delete_msg(self):
        # Creating new message
        response = requests.get(url=base_url + '/login', auth=HTTPBasicAuth('some_name', 'some_password'))
        headers = {'x-access-token': response.json()['token']}
        data_1_msg_test = {'receiver': '1_msg_receiver', 'subject': 'lets test get 1 msg',
                           'body': 'the message content 1 msg test'}
        requests.post(url=base_url + '/msg', headers=headers, json=data_1_msg_test)

        # Getting the last created message id
        response = requests.get(url=base_url + '/msg/all', headers=headers)
        msg_id = 0
        for msg in response.json()['messages']:
            if msg['id'] > msg_id:
                msg_id = msg['id']

        # Getting the last created message
        response = requests.get(url=base_url + '/msg/' + str(msg_id), headers=headers)
        self.assertIsInstance(response.json(), dict)
        self.assertEqual(response.status_code, 200)

        # Deleting the last created message
        response = requests.delete(url=base_url + '/msg/' + str(msg_id), headers=headers)
        self.assertIsInstance(response.json(), dict)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'message': 'Message item deleted!'})

        # Verifying that last message was deleted
        response = requests.get(url=base_url + '/msg/' + str(msg_id), headers=headers)
        self.assertIsInstance(response.json(), dict)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'message': 'No msg found!'})


if __name__ == '__main__':
    unittest.main()

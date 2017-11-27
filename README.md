# Shopping List Application API
[![Build Status](https://travis-ci.org/Sekams/shopping_list_api.svg?branch=master)](https://travis-ci.org/Sekams/shopping_list_api)
[![Coverage Status](https://coveralls.io/repos/github/Sekams/shopping_list_api/badge.svg?branch=master)](https://coveralls.io/github/Sekams/shopping_list_api?branch=master)

**The Shopping List Application API** is a REST API for serving data persistence methods to the Shopping List application.

## Progress Tracking
https://www.pivotaltracker.com/n/projects/2092508

## Live API
https://the-real-shopping-list-api.herokuapp.com/

## Getting Started
To be able to use the application locally, one should follow the guidelines highlighted below.

1. Clone/download the application Github repository by running the command below in a git shell
```
git clone https://github.com/Sekams/shopping_list_api.git
```
2. Set up a virtual environment (follow instructions at: http://python-guide-pt-br.readthedocs.io/en/latest/dev/virtualenvs/)

3. Install the application requirements by running the code below in the virtual environment:
```
pip install -r requirements.txt
```

4. Install Postgres SQL and create a database called _"shopping\_list\_api"_

5. Create the database tables by running the following command within the virtual environment:
```
python manage.py create_db
```

6. After all the requirements are installed on the local virtual environment, run the application by running the following code in the virtual environment:
```
python run.py
```
7. After successfully running the application, one can explore the features of the Shopping List Application API exploring the : http://127.0.0.1:5000 in any web browser of choice

## Features
* Account creation
* User session manegement (Login and Logout)
* Shopping list creation, management and deletion
* Shopping list item creation, management and deletion

## EndPoints

| Type | API EndPoint | Public Access | Description |
| --- | --- | --- | --- |
| POST | /v1/auth/register | TRUE | Registers a user and takes **username**, **email** and **password** as arguments |
| POST | /v1/auth/login | TRUE | Logs regitered users in and takes **username** and **password** as arguments |
| POST | /v1/auth/logout | TRUE | Logs logged in users out |
| POST | /v1/auth/reset-password | TRUE | Changes the password of a logged in user and takes **old\_password** and **new\_password** as arguments |
| POST | /v1/shoppinglists/ | FALSE | Saves a given shopping list to the database and takes **title** as an argument |
| GET | /v1/shoppinglists/\<int:limit\>/\<int:page\> | FALSE | Gets all shopping lists in the database |
| GET | /v1/shoppinglists/\<id\> | FALSE | Gets a shopping list with the provided id from the database |
| PUT | /v1/shoppinglists/\<id\> | FALSE | Edits shopping list with the provided id and takes **new\_title** as an argument |
| DELETE | /v1/shoppinglists/\<id\> | FALSE | Removes a shopping list with the provided id from the database |
| POST | /v1/shoppinglists/\<id\>/items/ | FALSE | Saves a given shopping list item to the database and takes **name**, **price** and **status** as arguments |
| GET | /v1/shoppinglists/\<id\>/items/\<int:limit\>/\<int:page\> | FALSE | Gets all shopping list items belonging to a given shopping list from the database |
| PUT | /v1/shoppinglists/\<id\>/items/\<item_id\>| FALSE | Edits shopping list item with the provided id and takes **new\_name**, **new\_price** and **new\_status** as arguments | 
| DELETE | /v1/shoppinglists/\<id\>/items/\<item_id\> | FALSE | Removes a shopping list item with the provided id from the database |
| GET | /v1/shoppinglists/search/shoppinglist/\<string:q\>/\<int:limit\>/\<int:page\> | FALSE | Searches for all shopping lists whose title starts with the query string **q** |
| GET | /v1/shoppinglists/search/item/\<string:q\>/\<int:limit\>/\<int:page\> | FALSE | Searches for all shopping list items whose name starts with the query string **q** |


## Testing
The application's tests can be executed by running the code below within the virtual environment:
```
python test_script.py
```

# Shopping List Application API
[![Build Status](https://travis-ci.org/Sekams/shopping_list_api.svg?branch=master)](https://travis-ci.org/Sekams/shopping_list_api)
[![Coverage Status](https://coveralls.io/repos/github/Sekams/shopping_list_api/badge.svg?branch=master)](https://coveralls.io/github/Sekams/shopping_list_api?branch=master)

**The Shopping List Application API** is a REST API for serving data persistence methods to the Shopping List application.

## Progress Tracking
https://www.pivotaltracker.com/n/projects/2092508

## Technologies
1. alembic==0.9.5
2. astroid==1.5.3
3. bcrypt==3.1.3
4. cffi==1.10.0
5. click==6.7
6. colorama==0.3.9
7. coverage==4.4.1
8. cryptography==1.7.2
9. Flask==0.12.2
10. Flask-API==0.7.1
11. Flask-Bcrypt==0.7.1
12. Flask-Migrate==2.1.0
13. Flask-Script==2.0.5
14. Flask-SQLAlchemy==2.2
15. Flask-Testing==0.6.2
16. gunicorn==19.7.1
17. idna==2.6
18. isort==4.2.15
19. itsdangerous==0.24
20. Jinja2==2.9.6
21. jwt==0.5.2
22. lazy-object-proxy==1.3.1
23. Mako==1.0.7
24. MarkupSafe==1.0
25. mccabe==0.6.1
26. nose==1.3.7
27. psycopg2==2.7.3
28. pyasn1==0.3.2
29. pycparser==2.18
30. PyJWT==1.5.2
31. pylint==1.7.2
32. python-dateutil==2.6.1
33. python-editor==1.0.3
34. six==1.10.0
35. SQLAlchemy==1.1.13
36. Werkzeug==0.12.2
37. wrapt==1.10.11
38. Python==3.6.1

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
4. After all the requirements are installed on the local virtual environment, run the application by running the following code in the virtual environment:
```
python run.py
```
5. After successfully running the application, one can explore the features of the Shopping List Application API exploring the : http://127.0.0.1:5000 in any web browser of choice

## Features
* Account creation
* User session manegement (Login and Logout)
* Shopping list creation, management and deletion
* Shopping list item creation, management and deletion

## EndPoints
| Type | API EndPoint | Public Access | Description |
| --- | --- | --- | --- |

| POST | /auth/register | TRUE | Registers a user and takes **username**, **email** and **password** as arguments |
| POST | /auth/login | TRUE | Logs regitered users in and takes **username** and **password** as arguments |
| POST | /auth/logout | TRUE | Logs logged in users out |
| POST | /auth/reset-password | Changes the password of a logged in user and takes **old_password** and **new_password** as arguments |
| POST | /shoppinglists/ | FALSE | Saves a given shopping list to the database |
| GET | /shoppinglists/ | FALSE | Gets all shopping lists in the database |
| GET | /shoppinglists/<id> | FALSE | Gets a shopping list with the provided id from the database |
| PUT | /shoppinglists/<id> | FALSE | Edits shopping list with the provided id |
| DELETE | /shoppinglists/<id> | FALSE | Removes a shopping list with the provided id from the database |
| POST | /shoppinglists/<id>/items/ | FALSE | Saves a given shopping list item to the database |
| PUT | /shoppinglists/<id>/items/<item_id>| FALSE | Edits shopping list item with the provided id | 
| DELETE | /shoppinglists/<id>/items/<item_id> | FALSE | Removes a shopping list item with the provided id from the database |


## Testing
The application's tests can be executed by running the code below within the virtual environment:
```
python test_script.py
```

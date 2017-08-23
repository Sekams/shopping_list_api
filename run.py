from server import create_app
from instance import instance

app = create_app(instance)

if __name__=='__main__':
    app.run()

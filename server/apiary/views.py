from flask import Blueprint, render_template as view

apiary = Blueprint('apiary', __name__, template_folder='templates')


@apiary.route('/')
def index():
    """
    Show an index template
    :return:
    """
    return view('index.html')
from flask import Blueprint


goals = Blueprint('goals', __name__)


from . import controllers, models

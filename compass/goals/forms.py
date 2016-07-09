from datetime import date

from flask.ext.wtf import Form
from wtforms.fields import (StringField, TextAreaField, DateField, SubmitField)
from wtforms.validators import NumberRange, Required, Length
from wtforms_components import DateField, DateRange, IntegerField

from .models import Goal


class GoalForm(Form):
    title = StringField("Title of Your Goal", validators=[Required(),
                                                          Length(1, 64)])
    description = TextAreaField("Describe Your Goal", validators=[Required()])
    target_time = DateField("Set the time for Your Goal",
                            validators=[DateRange(min=date.today())])
    difficulty = IntegerField("How difficult is this Goal",
                              validators=[NumberRange(min=1, max=7)])
    priority = IntegerField("Set the priority of this Goal",
                            validators=[NumberRange(min=1, max=7)])
    submit = SubmitField("Create Goal")

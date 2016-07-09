from datetime import datetime

from .. import db


class Goal(db.Model):
    __tablename__ = 'goals'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(64))
    description = db.Column(db.Text)
    created = db.Column(db.DateTime(), default=datetime.utcnow)
    achieved = db.Column(db.Boolean, default=False)
    # TODO - add option of selecting just month/year - maybe additional
    # table that consists of 'deadlines'
    target_time = db.Column(db.Date, nullable=True)
    difficulty = db.Column(db.Integer, nullable=True)
    priority = db.Column(db.Integer, nullable=True)

    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # TODO - add subgoals, steps, tasks

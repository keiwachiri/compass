from flask import render_template, url_for, redirect, g, flash

from .. import db
from ..auth.decorators import login_required
from . import goals
from .forms import GoalForm
from .models import Goal


@goals.route('/')
@login_required(redirect_to='auth.login')
def list_goals():
    user = g.user
    goals = user.goals
    form = GoalForm()
    return render_template('goals/list_goals.html', form=form,
                           goals=user.goals, user=user)


@goals.route('/', methods=['POST'])
@login_required(redirect_to='auth.login')
def create_goal():
    form = GoalForm()
    if form.validate_on_submit():
        goal = Goal(title=form.title.data,
                    description=form.description.data,
                    target_time=form.target_time.data,
                    difficulty=form.difficulty.data,
                    priority=form.priority.data,
                    user=g.user)
        db.session.add(goal)
        flash("Goal has been created successfully!")
    return redirect(url_for('goals.list_goals'))


@goals.route('/delete/<id>')
@login_required(redirect_to='auth.login')
def delete_goal(id):
    goal = Goal.query.get_or_404(id)
    if goal.user == g.user:
        db.session.delete(goal)
        flash("Goal has been deleted")
        return redirect(url_for('goals.list_goals'))
    else:
        flash("You have no rights to delete this goal")
        return redirect(url_for('main.index'))


@goals.route('/edit/<id>', methods=['POST'])
@login_required(redirect_to='auth.login')
def edit_goal(id):
    form = GoalForm()
    if form.validate_on_submit():
        goal = Goal.query.get_or_404(id)
        if g.user == goal.user:
            goal.title = form.title.data
            goal.description = form.description.data
            goal.target_time = form.target_time.data
            goal.difficulty = form.difficulty.data
            goal.priority = form.priority.data
            db.session.add(goal)
            flash("Goal successfully updated!")
            return redirect(url_for('goals.list_goals'))
        else:
            flash("This is not your goal!")
            return redirect(url_for('main.index'))
    return redirect(url_for('goals.list_goals'), form=form)

from __future__ import unicode_literals
from django.db import models
from datetime import datetime
from ..login_app.models import User

# Create your models here.
class TripManager(models.Manager):
    def addTrip(self, input, user):
        errors = []

        if len(input['destination']) == 0 or len(input['plan']) == 0 or len(input['start_date']) == 0 or len(input['end_date']) == 0:
            errors.append('Please do not leave any fields empty')

        if len(input['start_date']) > 0 or len(input['end_date']) > 0:
            start_date = datetime.strptime(input['start_date'], "%Y-%m-%d")
            end_date = datetime.strptime(input['end_date'], "%Y-%m-%d")

            if datetime.today() >= start_date:
                errors.append('Your start date must be today or later')
            if start_date > end_date:
                errors.append('Your end date cannot be earlier than today')

        if len(errors) == 0:
            trip = Trip.objects.create(destination=input['destination'], plan=input['plan'], user=user, start_date=start_date, end_date=end_date)
            trip.group.add(user)
            return (True, 'Your trip has been scheduled')

        else:
            return (False, errors)

    def joinTrip(self, trip_id, user):
        trip = Trip.objects.get(id=trip_id)
        trip.group.add(user)
        return (True, "You have joined the trip")


class Trip(models.Model):
    destination = models.CharField(max_length=50)
    plan = models.CharField(max_length=100)
    start_date = models.DateField()
    end_date = models.DateField()
    user = models.ForeignKey(User)
    group = models.ManyToManyField(User, related_name='travel')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = TripManager()

#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json() or {}

        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")

        errors = []
        if not username:
            errors.append("Username is required.")
        if not password:
            errors.append("Password is required.")

        if errors:
            return {"errors": errors}, 422

        try:
            new_user = User(
                username=username,
                image_url=image_url,
                bio=bio,
            )
            new_user.password_hash = password

            db.session.add(new_user)
            db.session.commit()

            # log the user in by saving ID in the session
            session["user_id"] = new_user.id

            return {
                "id": new_user.id,
                "username": new_user.username,
                "image_url": new_user.image_url,
                "bio": new_user.bio,
            }, 201

        except IntegrityError:
            db.session.rollback()
            return {"errors": ["Username must be unique."]}, 422

        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422



class CheckSession(Resource):
      def get(self):
        user_id = session.get("user_id")
        
        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = db.session.get(User, user_id)
        if not user:
            return {"error": "Unauthorized"}, 401

        return {
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }, 200

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio,
            }, 200

        return {"error": "Invalid username or password"}, 401


class Logout(Resource):
    def delete(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        session.pop("user_id", None)
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = db.session.get(User, user_id)
        if not user:
            return {"error": "Unauthorized"}, 401

        recipes = [
            {
                "id": r.id,
                "title": r.title,
                "instructions": r.instructions,
                "minutes_to_complete": r.minutes_to_complete,
            }
            for r in user.recipes
        ]
        return recipes, 200

    def post(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()
        try:
            recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id,
            )
            db.session.add(recipe)
            db.session.commit()

            return {
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
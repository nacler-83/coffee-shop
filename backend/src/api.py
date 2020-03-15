# ---------------------------------------------------------------------------#
# Imports
# ---------------------------------------------------------------------------#


import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth


# ---------------------------------------------------------------------------#
# App Config
# ---------------------------------------------------------------------------#


app = Flask(__name__)
setup_db(app)
CORS(app)
# uncomment the below to drop all records and start from scratch
# db_drop_and_create_all()


# ---------------------------------------------------------------------------#
# CORS
# ---------------------------------------------------------------------------#


@app.after_request
def after_request(response):
    header = response.headers
    header['Access-Control-Allow-Origin'] = '*'
    header['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, \
                                              true'
    header['Access-Control-Allow-Methods'] = 'POST,GET,PUT,DELETE,PATCH,\
                                              OPTIONS'
    return response


# ---------------------------------------------------------------------------#
# Routes
# ---------------------------------------------------------------------------#


# GET /drinks
@app.route('/drinks', methods=['GET'])
def get_drinks():
    '''
    Public endpoint that returns all the drinks in short form. No permissions
    needed. If no drinks are found return a 404. Otherwise return a 422.
    '''
    try:
        drinks = list(map(Drink.short, Drink.query.all()))

        if len(drinks) == 0:
            abort(404)

        result = {
            'success': True,
            'drinks': drinks
        }

        return jsonify(result), 200

    except(Exception):
        abort(422)


# GET /drinks-detail
@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drink_details(payload):
    '''
    Non-public endpoint requiring get:drink-details permission. Returns
    all the drinks in long form. If no drinks found return a 404. If auth
    error return a 401. Otherwise return 422.
    '''
    try:
        drinks = list(map(Drink.long, Drink.query.all()))

        if len(drinks) == 0:
            abort(404)

        result = {
            'success': True,
            'drinks': drinks
        }

        return jsonify(result), 200

    except AuthError:
        abort(401)

    except(Exception):
        abort(422)


# POST /drinks
@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def post_drinks(payload):
    '''
    Non-public endpoint requiring post:drinks permission. Allow user to
    create a new drink, with title and recipe. If successful return success
    and the drink in long format. If not authorized return a 401. Otherwise
    return a 422.
    '''
    try:
        body = request.get_json()
        title = body.get('title', None)
        recipe = body.get('recipe', None)

        drink = Drink(title=title, recipe=json.dumps(recipe))
        drink.insert()

        result = {
            'success': True,
            'drinks': drink.long()
        }

        return jsonify(result), 200

    except AuthError:
        abort(401)

    except(Exception):
        abort(422)


# PATCH /drinks/drink_id
@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(payload, drink_id):
    '''
    Non-public endpoint requiring the patch:drinks permission. Allow a user
    to update an existing drink with title and/or recipe. If successful
    return success and the drink in long form. If drink_id not found return
    a 404. If auth error return 401. Otherwise return 422.
    '''
    try:
        body = request.get_json()
        title = body.get('title', None)
        recipe = body.get('recipe', None)
        drink = Drink.query.filter(Drink.id == drink_id).one_or_none()

        if not drink:
            abort(404)

        if title:
            drink.title = title

        if recipe:
            drink.recipe = json.dumps(recipe)

        drink.update()
        drinks = list(map(Drink.long, Drink.query.all()))

        result = {
            'success': True,
            'drinks': drinks
        }

        return jsonify(result), 200

    except AuthError:
        abort(401)

    except(Exception):
        abort(422)


# DELETE /drinks/drink_id
@app.route('/drinks/<int:drink_id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drinks(payload, drink_id):
    '''
    Non-public endpoint requiring delete:drinks permission. Allow user to
    delete a drink by drink_id. If successful return success and the drink id.
    If auth error return 401. If drink not found by id return 404. Otherwise
    return 422.
    '''
    try:
        drink = Drink.query.get(drink_id)

        if not drink:
            abort(404)

        drink.delete()

        result = {
            'success': True,
            'delete': drink_id
        }

        return jsonify(result), 200

    except AuthError:
        abort(401)

    except(Exception):
        abort(422)


# ---------------------------------------------------------------------------#
# Error Handlers
# ---------------------------------------------------------------------------#

# 422
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
        }), 422


# 404
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
        }), 404


# AuthError
@app.errorhandler(AuthError)
def auth_error(e):
    return jsonify(e.error), e.status_code

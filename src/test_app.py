import pytest
from flask import Flask
from flask.testing import FlaskClient
from flask_login import current_user
from app import app, db, User, LoginForm, RegisterForm


@pytest.fixture(scope='module')
def test_client():
    app.config.from_object('config.TestConfig')
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.drop_all()


def test_index(test_client):
    response = test_client.get('/')
    assert response.status_code == 200


def test_sg_data(test_client):
    response = test_client.get('/sg_data')
    assert response.status_code == 200
    assert response.is_json
    data = response.get_json()
    assert isinstance(data, dict)
    assert 'sg_create_count' in data
    assert 'sg_delete_count' in data
    assert 'sg_modify_count' in data


def test_kms_data(test_client):
    response = test_client.get('/kms_data')
    assert response.status_code == 200
    assert response.is_json
    data = response.get_json()
    assert isinstance(data, dict)
    assert 'keys' in data
    assert 'rotation_count' in data
    assert len(data['keys']) == 2
    assert len(data['rotation_count']) == 2


def test_get_events_data(test_client):
    response = test_client.get('/get_events_data/5')
    assert response.status_code == 200
    assert response.is_json
    data = response.get_json()
    assert isinstance(data, dict)
    assert 'event_names' in data
    assert 'event_counts' in data
    assert len(data['event_names']) == 5
    assert len(data['event_counts']) == 5


def test_ec2_data(test_client):
    response = test_client.get('/ec2_data')
    assert response.status_code == 200
    assert response.is_json
    data = response.get_json()
    assert isinstance(data, dict)
    assert 'event_names' in data
    assert 'event_counts' in data
    assert len(data['event_names']) == 5
    assert len(data['event_counts']) == 5

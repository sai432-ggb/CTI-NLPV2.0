import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_analyze_url_malicious(client):
    response = client.post('/analyze_url', json={
        'url': 'http://malicious-phishing-site.tk'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['detection'] == 'MALICIOUS'
    assert data['risk_score'] > 60
    
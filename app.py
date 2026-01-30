"""
FarmRide - Farmer-Friendly Vehicle Booking Application
Main Flask Application with REST API
"""

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
import os
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'farmride-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///farmride.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)

# ==================== DATABASE MODELS ====================

class User(db.Model):
    """User model for farmers and admins"""
    __tablename__ = 'users'
    
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    phone_no = db.Column(db.String(15), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    village = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'user_id': self.user_id,
            'username': self.username,
            'phone_no': self.phone_no,
            'full_name': self.full_name,
            'village': self.village,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat()
        }


class Driver(db.Model):
    """Driver model with vehicle information"""
    __tablename__ = 'drivers'
    
    driver_id = db.Column(db.Integer, primary_key=True)
    driver_name = db.Column(db.String(100), nullable=False)
    phone_no = db.Column(db.String(15), nullable=False)
    vehicle_name = db.Column(db.String(100), nullable=False)
    vehicle_type = db.Column(db.String(50), nullable=False)  # tractor/truck/tempo/mini-truck
    vehicle_id = db.Column(db.String(50), unique=True, nullable=False)
    vehicle_photo = db.Column(db.String(200), default='default-vehicle.jpg')
    driver_photo = db.Column(db.String(200), default='default-driver.jpg')
    is_available = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    rides = db.relationship('Ride', backref='driver', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'driver_id': self.driver_id,
            'driver_name': self.driver_name,
            'phone_no': self.phone_no,
            'vehicle_name': self.vehicle_name,
            'vehicle_type': self.vehicle_type,
            'vehicle_id': self.vehicle_id,
            'vehicle_photo': self.vehicle_photo,
            'driver_photo': self.driver_photo,
            'is_available': self.is_available,
            'created_at': self.created_at.isoformat()
        }


class Ride(db.Model):
    """Ride model for booking transportation"""
    __tablename__ = 'rides'
    
    ride_id = db.Column(db.Integer, primary_key=True)
    driver_id = db.Column(db.Integer, db.ForeignKey('drivers.driver_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    driver_name = db.Column(db.String(100), nullable=False)
    vehicle_type = db.Column(db.String(50), nullable=False)
    vehicle_id = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    start_location = db.Column(db.String(200), nullable=False)
    destination = db.Column(db.String(200), nullable=False)
    ride_status = db.Column(db.String(20), default='available')  # available/booked/completed
    cargo_type = db.Column(db.String(100))  # manure/crops/produce
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'ride_id': self.ride_id,
            'driver_id': self.driver_id,
            'user_id': self.user_id,
            'driver_name': self.driver_name,
            'vehicle_type': self.vehicle_type,
            'vehicle_id': self.vehicle_id,
            'date': self.date.isoformat(),
            'time': self.time.isoformat(),
            'start_location': self.start_location,
            'destination': self.destination,
            'ride_status': self.ride_status,
            'cargo_type': self.cargo_type,
            'notes': self.notes,
            'created_at': self.created_at.isoformat()
        }


# ==================== AUTHENTICATION DECORATOR ====================

def token_required(f):
    """Decorator to protect routes with JWT authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Decode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated


def admin_required(f):
    """Decorator to restrict routes to admin users only"""
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    
    return decorated


# ==================== AUTHENTICATION ROUTES ====================
@app.route('/')
def index():
    return app.send_static_file('index.html')


@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'phone_no', 'password', 'full_name']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Check if user already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 409
        
        if User.query.filter_by(phone_no=data['phone_no']).first():
            return jsonify({'error': 'Phone number already registered'}), 409
        
        # Create new user
        user = User(
            username=data['username'],
            phone_no=data['phone_no'],
            full_name=data['full_name'],
            village=data.get('village', ''),
            is_admin=data.get('is_admin', False)
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
def login():
    """User login"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Find user
        user = User.query.filter_by(username=data['username']).first()
        
        if not user or not user.check_password(data['password']):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user.user_id,
            'username': user.username,
            'is_admin': user.is_admin,
            'exp': datetime.utcnow() + timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/logout', methods=['POST'])
@token_required
def logout(current_user):
    """User logout (client-side token removal)"""
    return jsonify({'message': 'Logout successful'}), 200


@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """Get current user profile"""
    return jsonify(current_user.to_dict()), 200


# ==================== DRIVER ROUTES ====================

@app.route('/api/drivers', methods=['GET'])
def get_drivers():
    """Get all drivers"""
    try:
        # Optional filters
        vehicle_type = request.args.get('vehicle_type')
        is_available = request.args.get('is_available')
        
        query = Driver.query
        
        if vehicle_type:
            query = query.filter_by(vehicle_type=vehicle_type)
        
        if is_available is not None:
            query = query.filter_by(is_available=is_available.lower() == 'true')
        
        drivers = query.all()
        
        return jsonify({
            'drivers': [driver.to_dict() for driver in drivers],
            'count': len(drivers)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/drivers/<int:driver_id>', methods=['GET'])
def get_driver(driver_id):
    """Get a specific driver"""
    try:
        driver = Driver.query.get(driver_id)
        
        if not driver:
            return jsonify({'error': 'Driver not found'}), 404
        
        return jsonify(driver.to_dict()), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/drivers', methods=['POST'])
@admin_required
def create_driver(current_user):
    """Create a new driver (admin only)"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['driver_name', 'phone_no', 'vehicle_name', 'vehicle_type', 'vehicle_id']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Check if vehicle_id already exists
        if Driver.query.filter_by(vehicle_id=data['vehicle_id']).first():
            return jsonify({'error': 'Vehicle ID already exists'}), 409
        
        # Create new driver
        driver = Driver(
            driver_name=data['driver_name'],
            phone_no=data['phone_no'],
            vehicle_name=data['vehicle_name'],
            vehicle_type=data['vehicle_type'],
            vehicle_id=data['vehicle_id'],
            vehicle_photo=data.get('vehicle_photo', 'default-vehicle.jpg'),
            driver_photo=data.get('driver_photo', 'default-driver.jpg'),
            is_available=data.get('is_available', True)
        )
        
        db.session.add(driver)
        db.session.commit()
        
        return jsonify({
            'message': 'Driver created successfully',
            'driver': driver.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/drivers/<int:driver_id>', methods=['PUT'])
@admin_required
def update_driver(current_user, driver_id):
    """Update a driver (admin only)"""
    try:
        driver = Driver.query.get(driver_id)
        
        if not driver:
            return jsonify({'error': 'Driver not found'}), 404
        
        data = request.get_json()
        
        # Update fields
        if 'driver_name' in data:
            driver.driver_name = data['driver_name']
        if 'phone_no' in data:
            driver.phone_no = data['phone_no']
        if 'vehicle_name' in data:
            driver.vehicle_name = data['vehicle_name']
        if 'vehicle_type' in data:
            driver.vehicle_type = data['vehicle_type']
        if 'vehicle_photo' in data:
            driver.vehicle_photo = data['vehicle_photo']
        if 'driver_photo' in data:
            driver.driver_photo = data['driver_photo']
        if 'is_available' in data:
            driver.is_available = data['is_available']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Driver updated successfully',
            'driver': driver.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/drivers/<int:driver_id>', methods=['DELETE'])
@admin_required
def delete_driver(current_user, driver_id):
    """Delete a driver (admin only)"""
    try:
        driver = Driver.query.get(driver_id)
        
        if not driver:
            return jsonify({'error': 'Driver not found'}), 404
        
        db.session.delete(driver)
        db.session.commit()
        
        return jsonify({'message': 'Driver deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==================== RIDE ROUTES ====================

@app.route('/api/rides', methods=['GET'])
def get_rides():
    """Get all rides"""
    try:
        # Optional filters
        ride_status = request.args.get('status')
        vehicle_type = request.args.get('vehicle_type')
        date_filter = request.args.get('date')
        
        query = Ride.query
        
        if ride_status:
            query = query.filter_by(ride_status=ride_status)
        
        if vehicle_type:
            query = query.filter_by(vehicle_type=vehicle_type)
        
        if date_filter:
            query = query.filter_by(date=datetime.fromisoformat(date_filter).date())
        
        rides = query.order_by(Ride.date.desc(), Ride.time.desc()).all()
        
        return jsonify({
            'rides': [ride.to_dict() for ride in rides],
            'count': len(rides)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/rides/<int:ride_id>', methods=['GET'])
def get_ride(ride_id):
    """Get a specific ride"""
    try:
        ride = Ride.query.get(ride_id)
        
        if not ride:
            return jsonify({'error': 'Ride not found'}), 404
        
        return jsonify(ride.to_dict()), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/rides', methods=['POST'])
@admin_required
def create_ride(current_user):
    """Create a new ride (admin only)"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['driver_id', 'date', 'time', 'start_location', 'destination']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Get driver information
        driver = Driver.query.get(data['driver_id'])
        if not driver:
            return jsonify({'error': 'Driver not found'}), 404
        
        # Create new ride
        ride = Ride(
            driver_id=data['driver_id'],
            driver_name=driver.driver_name,
            vehicle_type=driver.vehicle_type,
            vehicle_id=driver.vehicle_id,
            date=datetime.fromisoformat(data['date']).date(),
            time=datetime.fromisoformat(data['time']).time(),
            start_location=data['start_location'],
            destination=data['destination'],
            ride_status=data.get('ride_status', 'available'),
            cargo_type=data.get('cargo_type'),
            notes=data.get('notes')
        )
        
        db.session.add(ride)
        db.session.commit()
        
        return jsonify({
            'message': 'Ride created successfully',
            'ride': ride.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/rides/<int:ride_id>', methods=['PUT'])
@token_required
def update_ride(current_user, ride_id):
    """Update a ride"""
    try:
        ride = Ride.query.get(ride_id)
        
        if not ride:
            return jsonify({'error': 'Ride not found'}), 404
        
        data = request.get_json()
        
        # Update fields
        if 'date' in data:
            ride.date = datetime.fromisoformat(data['date']).date()
        if 'time' in data:
            ride.time = datetime.fromisoformat(data['time']).time()
        if 'start_location' in data:
            ride.start_location = data['start_location']
        if 'destination' in data:
            ride.destination = data['destination']
        if 'ride_status' in data:
            ride.ride_status = data['ride_status']
            # Update user_id when booking
            if data['ride_status'] == 'booked':
                ride.user_id = current_user.user_id
        if 'cargo_type' in data:
            ride.cargo_type = data['cargo_type']
        if 'notes' in data:
            ride.notes = data['notes']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Ride updated successfully',
            'ride': ride.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/rides/<int:ride_id>', methods=['DELETE'])
@admin_required
def delete_ride(current_user, ride_id):
    """Delete a ride (admin only)"""
    try:
        ride = Ride.query.get(ride_id)
        
        if not ride:
            return jsonify({'error': 'Ride not found'}), 404
        
        db.session.delete(ride)
        db.session.commit()
        
        return jsonify({'message': 'Ride deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/rides/<int:ride_id>/book', methods=['POST'])
@token_required
def book_ride(current_user, ride_id):
    """Book a ride"""
    try:
        ride = Ride.query.get(ride_id)
        
        if not ride:
            return jsonify({'error': 'Ride not found'}), 404
        
        if ride.ride_status != 'available':
            return jsonify({'error': 'Ride is not available for booking'}), 400
        
        ride.ride_status = 'booked'
        ride.user_id = current_user.user_id
        
        db.session.commit()
        
        return jsonify({
            'message': 'Ride booked successfully',
            'ride': ride.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==================== DASHBOARD ROUTES ====================

@app.route('/api/dashboard/farmer', methods=['GET'])
@token_required
def farmer_dashboard(current_user):
    """Get farmer dashboard data"""
    try:
        # Get user's booked rides
        my_rides = Ride.query.filter_by(user_id=current_user.user_id).all()
        
        # Get available rides
        available_rides = Ride.query.filter_by(ride_status='available').order_by(Ride.date, Ride.time).all()
        
        # Get all drivers
        drivers = Driver.query.filter_by(is_available=True).all()
        
        return jsonify({
            'user': current_user.to_dict(),
            'my_rides': [ride.to_dict() for ride in my_rides],
            'available_rides': [ride.to_dict() for ride in available_rides],
            'drivers': [driver.to_dict() for driver in drivers],
            'stats': {
                'total_rides': len(my_rides),
                'active_rides': len([r for r in my_rides if r.ride_status == 'booked']),
                'completed_rides': len([r for r in my_rides if r.ride_status == 'completed'])
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/admin', methods=['GET'])
@admin_required
def admin_dashboard(current_user):
    """Get admin dashboard data"""
    try:
        # Get all statistics
        total_drivers = Driver.query.count()
        available_drivers = Driver.query.filter_by(is_available=True).count()
        total_rides = Ride.query.count()
        available_rides = Ride.query.filter_by(ride_status='available').count()
        booked_rides = Ride.query.filter_by(ride_status='booked').count()
        completed_rides = Ride.query.filter_by(ride_status='completed').count()
        
        # Get recent rides
        recent_rides = Ride.query.order_by(Ride.created_at.desc()).limit(10).all()
        
        return jsonify({
            'stats': {
                'total_drivers': total_drivers,
                'available_drivers': available_drivers,
                'total_rides': total_rides,
                'available_rides': available_rides,
                'booked_rides': booked_rides,
                'completed_rides': completed_rides
            },
            'recent_rides': [ride.to_dict() for ride in recent_rides]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== HEALTH CHECK ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check"""
    return jsonify({
        'status': 'healthy',
        'message': 'FarmRide API is running',
        'timestamp': datetime.utcnow().isoformat()
    }), 200


# ==================== DATABASE INITIALIZATION ====================

def init_db():
    """Initialize database with sample data"""
    with app.app_context():
        db.create_all()
        
        # Check if data already exists
        if User.query.first() is None:
            # Create sample admin user
            admin = User(
                username='admin',
                phone_no='9876543210',
                full_name='Admin User',
                village='Nashik',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            
            # Create sample farmer
            farmer = User(
                username='ramesh',
                phone_no='9876543211',
                full_name='Ramesh Patil',
                village='Trimbakeshwar',
                is_admin=False
            )
            farmer.set_password('farmer123')
            db.session.add(farmer)
            
            # Create sample drivers
            drivers_data = [
                {
                    'driver_name': 'Suresh Jadhav',
                    'phone_no': '9876543220',
                    'vehicle_name': 'John Deere 5050D',
                    'vehicle_type': 'tractor',
                    'vehicle_id': 'MH15-TR-1234',
                    'vehicle_photo': 'https://images.unsplash.com/photo-1625246333195-78d9c38ad449?w=400',
                    'driver_photo': 'https://i.pravatar.cc/150?img=12'
                },
                {
                    'driver_name': 'Vikram Singh',
                    'phone_no': '9876543221',
                    'vehicle_name': 'Tata 407',
                    'vehicle_type': 'mini-truck',
                    'vehicle_id': 'MH15-MT-5678',
                    'vehicle_photo': 'https://images.unsplash.com/photo-1601584115197-04ecc0da31d7?w=400',
                    'driver_photo': 'https://i.pravatar.cc/150?img=33'
                },
                {
                    'driver_name': 'Prakash More',
                    'phone_no': '9876543222',
                    'vehicle_name': 'Mahindra Bolero Pickup',
                    'vehicle_type': 'tempo',
                    'vehicle_id': 'MH15-TP-9012',
                    'vehicle_photo': 'https://images.unsplash.com/photo-1519003722824-194d4455a60c?w=400',
                    'driver_photo': 'https://i.pravatar.cc/150?img=51'
                },
                {
                    'driver_name': 'Ganesh Desai',
                    'phone_no': '9876543223',
                    'vehicle_name': 'Eicher Pro 2049',
                    'vehicle_type': 'truck',
                    'vehicle_id': 'MH15-TK-3456',
                    'vehicle_photo': 'https://images.unsplash.com/photo-1601584115197-04ecc0da31d7?w=400',
                    'driver_photo': 'https://i.pravatar.cc/150?img=68'
                }
            ]
            
            for driver_data in drivers_data:
                driver = Driver(**driver_data)
                db.session.add(driver)
            
            db.session.commit()
            
            # Create sample rides
            drivers = Driver.query.all()
            rides_data = [
                {
                    'driver_id': drivers[0].driver_id,
                    'driver_name': drivers[0].driver_name,
                    'vehicle_type': drivers[0].vehicle_type,
                    'vehicle_id': drivers[0].vehicle_id,
                    'date': (datetime.now() + timedelta(days=1)).date(),
                    'time': datetime.strptime('08:00', '%H:%M').time(),
                    'start_location': 'Nashik Market',
                    'destination': 'Trimbakeshwar',
                    'ride_status': 'available',
                    'cargo_type': 'manure'
                },
                {
                    'driver_id': drivers[1].driver_id,
                    'driver_name': drivers[1].driver_name,
                    'vehicle_type': drivers[1].vehicle_type,
                    'vehicle_id': drivers[1].vehicle_id,
                    'date': (datetime.now() + timedelta(days=2)).date(),
                    'time': datetime.strptime('10:00', '%H:%M').time(),
                    'start_location': 'Igatpuri',
                    'destination': 'Nashik APMC',
                    'ride_status': 'available',
                    'cargo_type': 'crops'
                },
                {
                    'driver_id': drivers[2].driver_id,
                    'driver_name': drivers[2].driver_name,
                    'vehicle_type': drivers[2].vehicle_type,
                    'vehicle_id': drivers[2].vehicle_id,
                    'date': datetime.now().date(),
                    'time': datetime.strptime('14:00', '%H:%M').time(),
                    'start_location': 'Malegaon',
                    'destination': 'Mumbai Market',
                    'ride_status': 'booked',
                    'cargo_type': 'produce',
                    'user_id': farmer.user_id
                }
            ]
            
            for ride_data in rides_data:
                ride = Ride(**ride_data)
                db.session.add(ride)
            
            db.session.commit()
            
            print('✅ Database initialized with sample data')
            print('📝 Admin login: username=admin, password=admin123')
            print('📝 Farmer login: username=ramesh, password=farmer123')


# ==================== RUN APPLICATION ====================

if __name__ == '__main__':
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)

from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, IntegerField, SelectField
from wtforms import PasswordField
from wtforms import DateField
from wtforms import TextAreaField
from wtforms import BooleanField
from wtforms import SubmitField
from wtforms.validators import DataRequired, ValidationError, Length, EqualTo, Email, Regexp, NumberRange, URL
from flask_wtf.file import FileField, FileRequired


# 注册
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message='Username can not be empty!'),
                                                   Length(min=3, max=20, message='The length must between 3 to 20!')])
    email = StringField('Email', validators=[DataRequired(message='Email can not be empty!'),
                                             Email(message='Please enter a valid email address!')])
    password = PasswordField('Password', validators=[DataRequired(message='Password can not be empty!'),
                                                     Length(min=8, max=12, message='The length must between 8 to 12!'),
                                                     Regexp(
                                                         r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]+$',
                                                         message='The password must contain letters and numbers'
                                                                 '(like:password1)')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(message='Password can not be empty!'),
                                                                     EqualTo('password',
                                                                             message='Password inconsistency')])
    submit = SubmitField('Register')


# 登录
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message='Username can not be empty!'),
                                                   Length(min=3, max=20, message='The length must between 3 to 20!')])

    password = PasswordField('Password', validators=[DataRequired(message='Password can not be empty!'),
                                                     Length(min=8, message='The length must be at least 8!'),
                                                     Regexp(
                                                         r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]+$',
                                                         message='The password must contain letters and numbers'
                                                                 '(like:password1)')])
    submit = SubmitField('Login')


# 修改个人信息
class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message='Username can not be empty!'),
                                                   Length(min=3, max=20, message='The length must between 3 to 20!')])
    email = StringField('Email', validators=[DataRequired(message='Email can not be empty!'),
                                             Email(message='Please enter a valid email address!')])


class PasswordForm(FlaskForm):
    current_password = PasswordField('Password', validators=[DataRequired(message='Password can not be empty!'),
                                                     Length(min=8, max=12, message='The length must between 8 to 12!'),
                                                     Regexp(
                                                         r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]+$',
                                                         message='The password must contain letters and numbers'
                                                                 '(like:password1)')])
    new_password = PasswordField('Password', validators=[DataRequired(message='Password can not be empty!'),
                                                             Length(min=8, max=12,
                                                                    message='The length must between 8 to 12!'),
                                                             Regexp(
                                                                 r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]+$',
                                                                 message='The password must contain letters and numbers'
                                                                         '(like:password1)')])
    confirm_new_password = PasswordField('Confirm Password', validators=[DataRequired(message='Password can not be empty!'),
                                                                     EqualTo('password',
                                                                             message='Password inconsistency')])


# 地址
class AddressForm(FlaskForm):
    contact_name = StringField(
        'Contact Name',
        validators=[
            DataRequired(message='Contact name is required'),
            Length(max=50, message='Name cannot exceed 50 characters')
        ]
    )
    phone_number = StringField(
        'Phone Number',
        validators=[
            DataRequired(message='Phone number is required'),
            Regexp(r'^\d{11}$', message='Please enter a valid 11-digit phone number')
        ]
    )
    country = StringField(
        'Country/Region',
        validators=[
            DataRequired(message='Country/Region is required'),
            Length(max=100, message='Country/Region cannot exceed 100 characters')
        ]
    )
    city = StringField(
        'City',
        validators=[
            DataRequired(message='City is required'),
            Length(max=100, message='City cannot exceed 100 characters')
        ]
    )
    detailed_address = StringField(
        'Detailed Address',
        validators=[
            DataRequired(message='Detailed address is required'),
            Length(max=300, message='Address cannot exceed 300 characters')
        ]
    )
    is_default = BooleanField('Set as Default Address')  # Optional field
    submit = SubmitField('Save Address')


class ProductForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[DataRequired(message="Name is required."),
                    Length(max=100, message="Name cannot exceed 100 characters.")]
    )
    size = StringField(
        "Size",
        validators=[DataRequired(message="Size is required."),
                    Length(max=100, message="Size cannot exceed 100 characters.")]
    )
    taste = StringField(
        "Taste",
        validators=[Length(max=100, message="Taste cannot exceed 100 characters.")]
    )
    description = TextAreaField(
        "Description",
        validators=[Length(max=800, message="Description cannot exceed 800 characters.")]
    )
    price = FloatField(
        "Price",
        validators=[DataRequired(message="Price is required."),
                    NumberRange(min=0, message="Price must be a positive number.")]
    )
    submit = SubmitField("Update")


class CreateForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[DataRequired(message="Name is required."), Length(max=100, message="Name cannot exceed 100 characters.")]
    )
    size = StringField(
        "Size",
        validators=[DataRequired(message="Size is required."), Length(max=100, message="Size cannot exceed 100 characters.")]
    )
    taste = StringField(
        "Taste",
        validators=[Length(max=100, message="Taste cannot exceed 100 characters.")]
    )
    description = TextAreaField(
        "Description",
        validators=[Length(max=800, message="Description cannot exceed 800 characters.")]
    )
    price = FloatField(
        "Price",
        validators=[DataRequired(message="Price is required."), NumberRange(min=0, message="Price must be a positive number.")]
    )
    image_url = FileField(
        "Upload Image",
        validators=[DataRequired(message="Please upload an image.")]
    )
    category_id = SelectField(
        "Category",
        choices=[('1', 'cake'), ('2', 'bread'), ('3', 'pastry'), ('4', 'accessories')],
        coerce=int,
        validators=[DataRequired(message="Category selection is required.")]
    )
    submit = SubmitField("Submit")
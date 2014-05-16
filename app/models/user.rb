class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  # def configure_permitted_parameters
  # 	devise_parameter_sanitizer.for(:sign_in) { |u| u.permit(:first_name, :last_name, :profile_name, :email, :password, :password_confirmation) }
  # end
end

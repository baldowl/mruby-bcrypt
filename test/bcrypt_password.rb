##
## BCrypt::Password Test
##

BCrypt::Engine.cost = BCrypt::Engine::MIN_COST

plain_text_password = 'plain text password'
valid_hash = '$2b$04$ia18AcnE/QN7sWTKb3tYlO72JG6sdXl5uxnOdK2SEyilpQf7Hugk.'
version = '2b'
cost = 4
settings = '$2b$04$ia18AcnE/QN7sWTKb3tYlO'
checksum = '72JG6sdXl5uxnOdK2SEyilpQf7Hugk.'

invalid_hash = 'clearly invalid'

assert 'BCrypt::Password.valid_hash?' do
  assert_true BCrypt::Password.valid_hash?(valid_hash)
  assert_false BCrypt::Password.valid_hash?(invalid_hash)
end

assert 'BCrypt::Password.new' do
  assert_kind_of BCrypt::Password, BCrypt::Password.new(valid_hash)
  assert_raise(ArgumentError) { BCrypt::Password.new invalid_hash }

  password_object = BCrypt::Password.new valid_hash

  assert_equal version, password_object.version
  assert_equal cost, password_object.cost
  assert_equal settings, password_object.salt
  assert_equal checksum, password_object.checksum
end

assert 'BCrypt::Password.create' do
  assert_kind_of BCrypt::Password, BCrypt::Password.create(plain_text_password)
  assert_kind_of BCrypt::Password, BCrypt::Password.create(nil)
  assert_kind_of BCrypt::Password, BCrypt::Password.create(false)
  assert_kind_of BCrypt::Password, BCrypt::Password.create({:woo => "yeah"})

  password_object = BCrypt::Password.create plain_text_password, :cost => 5
  assert_not_equal BCrypt::Engine.cost, password_object.cost
end

assert 'BCrypt::Password#to_s' do
  assert_kind_of String, BCrypt::Password.new(valid_hash).to_s
end

assert 'BCrypt::Password#==' do
  password_object = BCrypt::Password.new valid_hash
  assert_true password_object == plain_text_password
  assert_true password_object.is_password?(plain_text_password)

  assert_false password_object == 'not the right password'
  assert_false password_object.is_password?('not the right password')
end

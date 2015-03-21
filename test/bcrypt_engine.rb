##
## BCrypt::Engine Test
##

assert 'BCrypt::Engine.__bc_random_bytes' do
  [0, 1, 2, 15].each do |requested_bytes|
    random_bytes = BCrypt::Engine.__bc_random_bytes requested_bytes
    assert_kind_of String, random_bytes
    assert_equal requested_bytes, random_bytes.length
  end

  assert_raise(ArgumentError) { BCrypt::Engine.__bc_random_bytes }
  assert_raise(ArgumentError) { BCrypt::Engine.__bc_random_bytes(-1) }
  assert_raise(TypeError) { BCrypt::Engine.__bc_random_bytes 'hello' }
end

assert 'BCrypt::Engine.__bc_salt' do
  prefix = '$2b$'
  cost = BCrypt::Engine::MAX_COST
  input = BCrypt::Engine.__bc_random_bytes BCrypt::Engine::RANDOM_BYTES

  settings = BCrypt::Engine.__bc_salt prefix, cost, input
  assert_kind_of String, settings
  assert_equal 29, settings.length

  _, version, settings_cost, salt = settings.split '$'
  assert_equal '2b', version
  assert_equal cost, settings_cost.to_i
  assert_equal 22, salt.length

  [0, *(BCrypt::Engine::MIN_COST..BCrypt::Engine::MAX_COST)].each do |valid_cost|
    assert_nothing_raised { BCrypt::Engine.__bc_salt prefix, valid_cost, input }
    assert_equal 29, BCrypt::Engine.__bc_salt(prefix, valid_cost, input).length
  end

  assert_raise(ArgumentError) { BCrypt::Engine.__bc_salt }
  assert_raise(ArgumentError) { BCrypt::Engine.__bc_salt prefix }
  assert_raise(ArgumentError) { BCrypt::Engine.__bc_salt prefix, cost }

  assert_raise(RuntimeError) { BCrypt::Engine.__bc_salt 'invalid', cost, input }

  # Valid costs are 0 and 4..31
  [-1, 1, 2, 3, 32, 33].each do |invalid_cost|
    assert_raise(RuntimeError) { BCrypt::Engine.__bc_salt prefix, invalid_cost, input }
  end

  too_short_input = input[0..14]
  assert_raise(RuntimeError) { BCrypt::Engine.__bc_salt prefix, cost, too_short_input }
end

assert 'BCrypt::Engine.hash_secret' do
  plain_password = 'plain text password'
  # Pre-computed for consistency's sake :)
  settings = '$2b$04$ia18AcnE/QN7sWTKb3tYlO'
  precomputed_hashed_password = '$2b$04$ia18AcnE/QN7sWTKb3tYlO72JG6sdXl5uxnOdK2SEyilpQf7Hugk.'

  hashed_password = BCrypt::Engine.hash_secret plain_password, settings
  assert_kind_of String, hashed_password
  assert_equal precomputed_hashed_password, hashed_password

  crypto_blob = hashed_password.split('$')[-1]
  salt_from_settings = settings.split('$').last
  salt_from_crypto_blob = crypto_blob[0..21]
  assert_equal salt_from_settings, salt_from_crypto_blob

  assert_raise(TypeError) { BCrypt::Engine.hash_secret nil, settings }
  assert_raise(TypeError) { BCrypt::Engine.hash_secret plain_password, nil }

  assert_raise(RuntimeError) { BCrypt::Engine.hash_secret plain_password, 'invalid settings' }
end

assert 'BCrypt::Engine.cost' do
  assert_true !BCrypt::Engine.cost.nil?
  assert_kind_of Integer, BCrypt::Engine.cost
end

assert 'BCrypt::Engine.valid_cost?' do
  assert_true BCrypt::Engine.valid_cost?(0)

  (BCrypt::Engine::MIN_COST..BCrypt::Engine::MAX_COST).each do |cost|
    assert_true BCrypt::Engine.valid_cost?(cost)
  end

  assert_false BCrypt::Engine.valid_cost?(nil)
  assert_false BCrypt::Engine.valid_cost?([])
  assert_false BCrypt::Engine.valid_cost?(BCrypt::Engine::MIN_COST - 1)
  assert_false BCrypt::Engine.valid_cost?(BCrypt::Engine::MAX_COST + 1)
end

assert 'BCrypt::Engine.cost=' do
  new_cost = 20

  BCrypt::Engine.cost = 20
  assert_equal new_cost, BCrypt::Engine.cost

  BCrypt::Engine.cost = 'not a number'
  assert_equal 0, BCrypt::Engine.cost

  [
    nil,
    [],
    BCrypt::Engine::MIN_COST - 1,
    BCrypt::Engine::MAX_COST + 1
  ].each do |invalid_cost|
    BCrypt::Engine.cost = invalid_cost
    assert_equal BCrypt::Engine::DEFAULT_COST, BCrypt::Engine.cost
  end
end

assert 'BCrypt::Engine.generate_salt' do
  assert_kind_of String, BCrypt::Engine.generate_salt

  assert_not_equal BCrypt::Engine.generate_salt, BCrypt::Engine.generate_salt

  special_cost_picked_by_implementation = '05'
  [0, 'not a number'].each do |special_cost|
    assert_equal special_cost_picked_by_implementation,
      BCrypt::Engine.generate_salt(special_cost).split('$')[2]
  end

  [
    nil,
    [],
    BCrypt::Engine::MIN_COST - 1,
    BCrypt::Engine::MAX_COST + 1
  ].each do |invalid_cost|
    salt = BCrypt::Engine.generate_salt invalid_cost
    assert_equal BCrypt::Engine::DEFAULT_COST.to_s, salt.split('$')[2]
  end
end

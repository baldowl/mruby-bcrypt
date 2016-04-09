module BCrypt
  # A Ruby wrapper for OpenBSD's bcrypt.c extension.
  class Engine
    # The default computational cost.
    DEFAULT_COST = 10
    # Algorithm's lowest cost
    MIN_COST     = 4
    # Current implementation's highest cost
    MAX_COST     = 31
    RANDOM_BYTES = 16

    @cost = nil

    ##
    # call-seq:
    #    BCrypt::Engine.cost    -> int
    #
    # Returns the cost factor that will be used if one is not specified when
    # creating a hash.
    #
    # Defaults to +DEFAULT_COST+ if not set.
    def self.cost
      @cost || DEFAULT_COST
    end

    ##
    # call-seq:
    #    BCrypt::Engine.valid_cost?(cost)    -> true or false
    #
    # Returns true if +cost+ is valid, i.e., 0 or an integer value between
    # +MIN_COST+ and +MAX_COST+.
    def self.valid_cost? cost
      return false unless cost.respond_to?(:to_i)
      cost = cost.to_i
      cost == 0 || (MIN_COST..MAX_COST).include?(cost)
    end

    ##
    # call-seq:
    #    BCrypt::Engine.cost = cost    -> cost or DEFAULT_COST
    #
    # Sets the cost factor that will be used if one is not specified when
    # creating a hash.
    #
    # Invalid cost factors are silently ignored and the system falls back to
    # +DEFAULT_COST+.
    def self.cost=(cost)
      @cost = valid_cost?(cost) ? cost.to_i : DEFAULT_COST
    end

    ##
    # call-seq:
    #    BCrypt::Engine.generate_salt          -> salt string
    #    BCrypt::Engine.generate_salt(cost)    -> salt string
    #
    # Given an optional +cost+ factor, it generates a random salt string
    # (which includes algorithm's version and cost factor).
    #
    # BCrypt::Engine.cost is used when called without an explicit +cost+
    # factor. +DEFAULT_COST+ is used when called with an invalid +cost+
    # factor.
    def self.generate_salt(cost = self.cost)
      cost = valid_cost?(cost) ? cost.to_i : DEFAULT_COST
      __bc_salt '$2b$', cost, __bc_random_bytes(RANDOM_BYTES)
    end

    ##
    # call-seq:
    #    BCrypt::Engine.calibrate(int)    -> int
    #
    # Calculates the cost factor which will result in computation times less
    # than +upper_time_limit_in_ms+ on the current system/hardware.
    #
    #   BCrypt::Engine.calibrate(200)  #=> 12
    #   BCrypt::Engine.calibrate(1000) #=> 14
    def self.calibrate upper_time_limit_in_ms
      (MIN_COST..MAX_COST).each do |current_cost|
        start_time = Time.now
        Password.create 'plain text password', :cost => current_cost
        elapsed_time = (Time.now - start_time) * 1000
        previous_cost = current_cost > MIN_COST ? current_cost - 1 : current_cost
        return previous_cost if elapsed_time > upper_time_limit_in_ms
      end
    end
  end
end

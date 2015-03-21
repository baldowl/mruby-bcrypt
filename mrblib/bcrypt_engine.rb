module BCrypt
  class Engine
    DEFAULT_COST = 10
    # Algorithm's lower limit
    MIN_COST     = 4
    # Implementation's upper limit
    MAX_COST     = 31
    RANDOM_BYTES = 16

    @cost = nil

    def self.cost
      @cost || DEFAULT_COST
    end

    def self.valid_cost? cost
      return false unless cost.respond_to?(:to_i)
      cost = cost.to_i
      cost == 0 || (MIN_COST..MAX_COST).include?(cost)
    end

    # MAYBE: what about raising an exception if it's invalid?
    def self.cost=(cost)
      @cost = valid_cost?(cost) ? cost.to_i : DEFAULT_COST
    end

    # MAYBE: what about raising an exception if it's invalid?
    def self.generate_salt(cost = self.cost)
      cost = valid_cost?(cost) ? cost.to_i : DEFAULT_COST
      __bc_salt '$2b$', cost, __bc_random_bytes(RANDOM_BYTES)
    end

    # FIXME: ugly! An easy fix would be to make gerate_salt use MIN_COST
    # instead of DEFAULT_COST and start from 1 (not 0 because it allows the
    # implementation to choose a default cost equals to 5).
    def self.calibrate upper_time_limit_in_ms
      previous_cost = MIN_COST
      (MIN_COST..MAX_COST).each do |i|
        start_time = Time.now
        Password.create 'plain text password', :cost => i
        elapsed_time = (Time.now - start_time) * 1000
        return previous_cost if elapsed_time > upper_time_limit_in_ms
        previous_cost = i
      end
    end
  end
end

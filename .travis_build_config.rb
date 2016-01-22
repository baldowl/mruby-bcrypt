MRuby::Build.new do |conf|
  toolchain :gcc
  enable_debug
  conf.gembox 'default'
  conf.gem '.'
  conf.enable_test if conf.respond_to?(:enable_test)
end

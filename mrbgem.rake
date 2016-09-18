MRuby::Gem::Specification.new 'mruby-bcrypt' do |spec|
  spec.license = 'MIT'
  spec.authors = 'Emanuele Vicentini'
  spec.summary = 'OpenBSD-style Blowfish-based password hashing'
  spec.homepage = 'https://github.com/baldowl/mruby-bcrypt'

  spec.objs += Dir.glob("#{spec.dir}/src/crypt_blowfish/*.[cS]").
    map{|f| f.relative_path_from(dir).pathmap("#{build_dir}/%X.o")}

  spec.add_dependency 'mruby-onig-regexp',
    :github => 'mattn/mruby-onig-regexp',
    :checksum_hash => '0a3e9954c20da9077196d19515c585e8f706be5e'

  if build.respond_to?(:test_enabled?) && build.test_enabled?
    spec.add_dependency 'mruby-time'
  end

  spec.linker.libraries << 'crypto' unless RUBY_PLATFORM =~ /darwin/
end

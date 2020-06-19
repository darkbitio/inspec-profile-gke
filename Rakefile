# frozen_string_literal: true

require 'rake/testtask'
require 'rubocop/rake_task'

# run tests
desc 'Runs :lint and :check'
task default: [:lint, :check]

# Rubocop
desc 'Run Rubocop lint checks'
task :rubocop do
  RuboCop::RakeTask.new
end

# lint the project
desc 'Run robocop linter'
task lint: [:rubocop]

# Lint the profile
desc 'Checks the profile for Inspec linting'
task :check do
  dir = File.join(File.dirname(__FILE__))
  sh("inspec check #{dir}")
end

# Run the profile
desc 'Runs the profile'
task :run do
  dir = File.join(File.dirname(__FILE__))
  sh("inspec exec #{dir} -t local:// --input-file=#{dir}/inputs.yml")
end

# Run the profile w JSON
desc 'Runs the profile'
task :runjson do
  dir = File.join(File.dirname(__FILE__))
  sh("inspec exec #{dir} -t local:// --input-file=#{dir}/inputs.yml --reporter=json:- | jq -r")
end

# Runs the e2e pipeline
desc 'Runs e2e'
task :e2e do
  dir = File.join(File.dirname(__FILE__))
  sh("inspec exec #{dir} -t local:// --input-file=#{dir}/inputs.yml --reporter=json:- | ../assessment-tools/inspec/inspec-results-parser.rb | ../assessment-tools/inspec/inspec-findings-formatter.rb | jq -r")
end

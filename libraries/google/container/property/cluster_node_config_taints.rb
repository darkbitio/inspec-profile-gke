# frozen_string_literal: false
# Modified/forked from https://github.com/inspec/inspec-gcp
# ----------------------------------------------------------------------------
#
#     ***     AUTO GENERATED CODE    ***    AUTO GENERATED CODE     ***
#
# ----------------------------------------------------------------------------
#
#     This file is automatically generated by Magic Modules and manual
#     changes will be clobbered when the file is regenerated.
#
#     Please read more about how to change this file in README.md and
#     CONTRIBUTING.md located at the root of this package.
#
# ----------------------------------------------------------------------------
module GoogleInSpec
  module Container
    module Property
      class ClusterNodeConfigTaints
        attr_reader :key

        attr_reader :value

        attr_reader :effect

        def initialize(args = nil, parent_identifier = nil)
          return if args.nil?
          @parent_identifier = parent_identifier
          @key = args['key']
          @value = args['value']
          @effect = args['effect']
        end

        def to_s
          "#{@parent_identifier} ClusterNodeConfigTaints"
        end
      end

      class ClusterNodeConfigTaintsArray
        def self.parse(value, parent_identifier)
          return if value.nil?
          return ClusterNodeConfigTaints.new(value, parent_identifier) unless value.is_a?(::Array)
          value.map { |v| ClusterNodeConfigTaints.new(v, parent_identifier) }
        end
      end
    end
  end
end
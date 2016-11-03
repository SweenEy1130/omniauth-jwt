require 'omniauth'
require 'jwt'

module OmniAuth
  module Strategies
    class Yufu
      class ClaimInvalid < StandardError; end
      
      include OmniAuth::Strategy
      
      args [:public_key]
      
      option :public_key, nil
      option :uid_field, 'sub'
      option :required_claims, %w()
      option :info_map, {"name" => "name", "email" => "email"}
      option :auth_url, nil
      
      def request_phase
        redirect options.auth_url
      end
      
      def decoded
        @decoded ||= ::JWT.decode(request.params['id_token'], OpenSSL::PKey::RSA.new(options.public_key))
        (options.required_claims || []).each do |field|
          raise ClaimInvalid.new("Missing required '#{field}' claim.") if !@decoded[0].key?(field.to_s)
        end
        raise ClaimInvalid.new("Missing required 'iat' claim.") if options.valid_within && !@decoded["iat"]
        @decoded
      end
      
      def callback_phase
        super
      rescue ClaimInvalid => e
        fail! :claim_invalid, e
      end

      uid do
        decoded[0][options.uid_field] 
      end
      
      extra do
        {:raw_info => decoded[0]}
      end
      
      info do
        options.info_map.inject({}) do |h,(k,v)|
          h[k.to_s] = decoded[0][v.to_s]
          h
        end
      end
    end
  end
end
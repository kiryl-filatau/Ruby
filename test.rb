require 'net/http'
require 'json'

ADDR='54.165.255.89'
PORT='8200'
KEY='afe9b2b52fd57f2e465456698fc46cdd56278ad810d6f0085fcc251d899c8827'
KB64='r+mytS/Vfy5GVFZpj8Rs3VYnitgQ1vAIX8wlHYmciCc='
RT='4ec70c21-5e6e-585e-7440-b6c64b8060c7'
PKI_NAME = "test6_pki"
ROLE_NAME= "test1_role"
CERT_CNAME= "test3.example.com"

########################### UNSEALING ############################
def get_health
  uri = URI("http://#{ADDR}:#{PORT}/v1/sys/health")
  res = Net::HTTP.get(uri)
  JSON.parse(res).to_hash
end

def unseal_vault
  uri = URI.parse("http://#{ADDR}:#{PORT}/v1/sys/unseal")
  req = Net::HTTP.new(uri.host, uri.port)
  headers = {"X-Vault-Token" => "#{RT}"}
  data = {"key": "#{KB64}"}.to_json
  resp = req.post(uri, data, headers)
end


if get_health["sealed"]
  puts "unsealing..."
  unseal_vault
else
  puts "unsealed"
end

########################### MOUNT PKI ############################

def check_mounts
  uri = URI.parse("http://#{ADDR}:#{PORT}/v1/sys/mounts")
  req = Net::HTTP::Get.new(uri)
  req['X-Vault-Token'] = "#{RT}"
  res = Net::HTTP.start(uri.hostname, uri.port) {|http|
    http.request(req)
  }
  JSON.parse(res.body).to_hash
end

def maunt_pki
  uri = URI.parse("http://#{ADDR}:#{PORT}/v1/sys/mounts/#{PKI_NAME}")
  req = Net::HTTP.new(uri.host, uri.port)
  headers = {"X-Vault-Token" => "#{RT}"}
  data = {"type": "pki"}.to_json
  resp = req.post(uri, data, headers)
end

if check_mounts["#{PKI_NAME}/"].nil? 
  puts "mounting pki..."
  maunt_pki
else
  puts "mounted"
end


########################### UPLOAD CA ###########################


def check_rootCA
  uri = URI.parse("http://#{ADDR}:#{PORT}/v1/#{PKI_NAME}/ca")
  req = Net::HTTP::Get.new(uri)
  req['X-Vault-Token'] = "#{RT}"
  res = Net::HTTP.start(uri.hostname, uri.port) {|http|
    http.request(req)
  }
end



def upload_rootCA
  uri = URI.parse("http://#{ADDR}:#{PORT}/v1/#{PKI_NAME}/config/ca")
  req = Net::HTTP.new(uri.host, uri.port)
  headers = {"X-Vault-Token" => "#{RT}"}
  data = File.read('rootCA_key.json')
  resp = req.post(uri, data, headers)
end


if (check_rootCA.to_s).include? "HTTPNoContent"
  puts "uploading CA..."
  upload_rootCA
else
  puts "CA uploaded"
end

########################### CREATE ROLE #########################

def check_role
  uri = URI.parse("http://#{ADDR}:#{PORT}/v1/#{PKI_NAME}/roles?list=true")
  req = Net::HTTP::Get.new(uri)
  req['X-Vault-Token'] = "#{RT}"
  res = Net::HTTP.start(uri.hostname, uri.port) {|http|
    http.request(req)
  }
  JSON.parse(res.body).to_hash
end


def create_role
  uri = URI.parse("http://#{ADDR}:#{PORT}/v1/#{PKI_NAME}/roles/#{ROLE_NAME}")
  req = Net::HTTP.new(uri.host, uri.port)
  headers = {"X-Vault-Token" => "#{RT}"}
  data = {"allowed_domains": ["example.com"],"allow_subdomains": true}.to_json
  resp = req.post(uri, data, headers)
end

p check_role["errors"]

if check_role["errors"].include? "[]"
  puts "no roles, creating first"
  create_role
elsif check_role["data"]["keys"].include? "#{ROLE_NAME}"
  puts "role exists"
else
  puts "creating role..."
  create_role
end

######################### ISSUING CERT ##########################

def check_cert
  uri = URI.parse("http://#{ADDR}:#{PORT}/v1/#{PKI_NAME}/certs?list=true")
  req = Net::HTTP::Get.new(uri)
  req['X-Vault-Token'] = "#{RT}"
  res = Net::HTTP.start(uri.hostname, uri.port) {|http|
    http.request(req)
  }
  JSON.parse(res.body).to_hash
end


def issue_cert
  uri = URI.parse("http://#{ADDR}:#{PORT}/v1/#{PKI_NAME}/issue/#{ROLE_NAME}")
  req = Net::HTTP.new(uri.host, uri.port)
  headers = {"X-Vault-Token" => "#{RT}"}
  data = {"common_name": "#{CERT_CNAME}"}.to_json
  resp = req.post(uri, data, headers)
  JSON.parse(resp.body).to_hash
end

PRIVATE_KEY = issue_cert["data"]["private_key"]
SERIAL_NUMBER = issue_cert["data"]["serial_number"]

puts "#{SERIAL_NUMBER} => #{PRIVATE_KEY}"



# if check_role["data"]["keys"].include? "#{ROLE_NAME}"
#   puts "cert exists"
# else
#   puts "issuing cert..."
#   create_role
# end

require './memento_client'

client = Memento::Client.new "../schema/memento-schema.rng", "homer-1.rkd.cw-ngv.com", "a", "a", "b"
puts client.get_call_list

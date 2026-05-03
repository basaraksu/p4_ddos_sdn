import sys
import os
import time
import threading
from receive_digest import receiveDigest

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../utils/'))

import p4runtime_lib.bmv2
import p4runtime_lib.helper


class switchWorkerThread(threading.Thread):
    def __init__(self, switch_name, grpc_port, device_id, controller, daemon=True):
        super().__init__(daemon=daemon)
        self.switch_name = switch_name
        self.grpc_port = grpc_port
        self.device_id = device_id
        self.controller = controller
        
    
    def setup_switch(self):
        # Switch bağlantısını kurma ve yapılandırma kodları burada olacak

        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(self.controller.p4info_file)
        self.switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=self.switch_name,
            address=f'127.0.0.1:{self.grpc_port}',
            device_id=self.device_id)
        
        self.switch.MasterArbitrationUpdate()
        
        digest_entry = self.p4info_helper.buildDigestEntry(digest_name="flow_features_t")
        self.switch.WriteDigestEntry(digest_entry)
        print(f"--- {self.switch_name} switch kurulumu tamamlandi ---") 

    def run(self):
        self.setup_switch()
        
        digest_service = receiveDigest(self.switch, self.controller)
        # while true dçngüsü içinde digest alma işlemi burada gerçekleşecek
        digest_service.receive_digest() 
        

    
import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(function () {
    send("Running Script");
    
    
    var checkAddr = undefined;
    exports = Module.enumerateExportsSync('libJniTest.so');
    for(i = 0;i<exports.length;i++) {
        if(exports[i].name == 'Java_demo2_jni_com_myapplication_myJNI_check'){
            checkAddr = exports[i].address
            send('check address:'+checkAddr)
            break
        }
    }

    Interceptor.attach (Module.findExportByName ( "libc.so", "strcmp"), {
            onEnter: function (args) {
            if(Memory.readUtf8String (args[1])=='308201dd30820146020101300d06092a864886f70d010105050030373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b3009060355040613025553301e170d3138303332313033303431385a170d3438303331333033303431385a30373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b300906035504061302555330819f300d06092a864886f70d010101050003818d00308189028181008270f53e2cf8c7d7ed200863deb85a054defde773be0b848ee792839d9a81da098dd9b74bbb9679c19ea30b63fe3bb74aabb270a5c9b3359ebe3fdf278b82fe576a6677f0d77f0eb5b088d0711b15d03cadae08b3b980f28055d0cde4bbc4a0b4b208b0f30f170b6ea77a8620269fa1d375442653663e1dd41293aa1c4910e350203010001300d06092a864886f70d010105050003818100044b9ab7e85346a147926c2d1c6c30e8ffcce174f88acb9763cb776fb1f4dd62183c9524346738ff1aea16c5fa218c68da76d05a2422aee12fc23563b5e28925c3d96dff855a584fc1ec462aa768277bd25739085d52fe3fedfd396e38180c13fbb289786e524535933dd8a99ed3154880544f3e41f044acc43ceefbbce3af59'){
                args[0] = args[1]
               
            }
            if(Memory.readUtf8String (args[1])=='koudai'){
                args[0] = args[1]
               //send('koudai:'+Memory.readUtf8String (args[0]))
            }
            if(Memory.readUtf8String (args[1])=='black'){
                args[0] = args[1]
               //send('black'+Memory.readUtf8String (args[0]))
            }
            
        },
            onLeave: function (retval) {
                //retval.replace(0);
        }
    });

    // Interceptor.attach(checkAddr,{
    //     onEnter:function(args){
    //         send('key is:'+Memory.readUtf8String(Memory.readPointer(checkAddr.sub(0xeb8).add(0xf68))))
    //     }
    // })
});
"""

process = frida.get_usb_device().attach('demo2.jni.com.myapplication')
script = process.create_script(jscode)
script.on('message', on_message)
script.load()
sys.stdin.read()
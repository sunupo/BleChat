/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.android.bluetoothchat;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;

import com.example.android.common.logger.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.UUID;

/**
 * This class does all the work for setting up and managing Bluetooth
 * connections with other devices. It has a thread that listens for
 * incoming connections, a thread for connecting with a device, and a
 * thread for performing data transmissions when connected.
 */
public class BluetoothChatService {
    // Debugging
    private static final String TAG = "BluetoothChatService";

    // Name for the SDP record when creating server socket
    private static final String NAME_SECURE = "BluetoothChatSecure";
    private static final String NAME_INSECURE = "BluetoothChatInsecure";

    // Unique UUID for this application
    private static final UUID MY_UUID_SECURE =
            UUID.fromString("fa87c0d0-afac-11de-8a39-0800200c9a66");
    private static final UUID MY_UUID_INSECURE =
            UUID.fromString("8ce255c0-200a-11e0-ac64-0800200c9a66");

    // Member fields
    private final BluetoothAdapter mAdapter;
    private final Handler mHandler;
    private AcceptThread mSecureAcceptThread;
    private AcceptThread mInsecureAcceptThread;
    private ConnectThread mConnectThread;
    private ConnectedThread mConnectedThread;
    private int mState;
    private int mNewState;

    // Constants that indicate the current connection state
    public static final int STATE_NONE = 0;       // we're doing nothing
    public static final int STATE_LISTEN = 1;     // now listening for incoming connections
    public static final int STATE_CONNECTING = 2; // now initiating an outgoing connection
    public static final int STATE_CONNECTED = 3;  // now connected to a remote device

    /**
     * Constructor. Prepares a new BluetoothChat session.
     *
     * @param context The UI Activity Context
     * @param handler A Handler to send messages back to the UI Activity
     */
    public BluetoothChatService(Context context, Handler handler) {
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mState = STATE_NONE;
        mNewState = mState;
        mHandler = handler;
    }

    /**
     * Update UI title according to the current state of the chat connection
     */
    //在BluetoothChatFragment中的handleMessage方法中会调用setStatus()方法去设置subTitle，actionBar.setSubtitle(subTitle);
    private synchronized void updateUserInterfaceTitle() {
        mState = getState();
        Log.d(TAG, "updateUserInterfaceTitle() " + mNewState + " -> " + mState);
        mNewState = mState;

        // Give the new state to the Handler so the UI Activity can update
        //从全局消息池返回一个新的Message对象Returns a new {@link android.os.Message Message} from the global message pool,
        // 然后Sends this Message to the Handler specified by {@link #getTarget}.
        mHandler.obtainMessage(Constants.MESSAGE_STATE_CHANGE, mNewState, -1).sendToTarget();
    }

    /**
     * Return the current connection state.
     */
    public synchronized int getState() {
        return mState;
    }

    /**
     * Start the chat service. Specifically start AcceptThread to begin a
     * session in listening (server) mode. Called by the Activity onResume()
     */
    //开始chat service 服务，启动一个AcceptThread为了以监听（服务器）模式开始一个session，
    //被Activity（BluetoothChatFragment）的onResume()调用
    // mChatService.start();
    //1.双向通信，两端都需要开启AcceptThread线程
    //2.单向通信，下位机远程device作为server端，监听App端的连接请求
    public synchronized void start() {
        Log.d(TAG, "start");

        // Cancel any thread attempting to make a connection
        //取消所有尝试连接的线程
        if (mConnectThread != null) {
            mConnectThread.cancel();
            mConnectThread = null;
        }

        // Cancel any thread currently running a connection
        //取消所有已连接的线程
        if (mConnectedThread != null) {
            mConnectedThread.cancel();
            mConnectedThread = null;
        }

        // Start the thread to listen on a BluetoothServerSocket
        //开始一个SecureAcceptThread线程，去监听BluetoothServerSocket
        if (mSecureAcceptThread == null) {
            mSecureAcceptThread = new AcceptThread(true);
            mSecureAcceptThread.start();
        }
        //开始一个InSecureAcceptThread线程，去监听BluetoothServerSocket
        if (mInsecureAcceptThread == null) {
            mInsecureAcceptThread = new AcceptThread(false);
            mInsecureAcceptThread.start();
        }
        // Update UI title
        updateUserInterfaceTitle();
    }

    /**
     * Start the ConnectThread to initiate a connection to a remote device.
     *
     * @param device The BluetoothDevice to connect
     * @param secure Socket Security type - Secure (true) , Insecure (false)
     */
    //开始一个连接线程ConnectThread，去初始化initiate一个远程设备的连接a connection to a remote device.
    //---------------------这儿没有关闭AcceptThread线程，我的理解是:-----------------------
    //1.双向通信，还需要保留监听服务
    //2.单向通信（app客户端发起connect连接，app没有监听服务；服务端应该不会发起connect请求）
    public synchronized void connect(BluetoothDevice device, boolean secure) {
        Log.d(TAG, "connect to: " + device);

        // Cancel any thread attempting to make a connection
        //当前状态mState是正在连接STATE_CONNECTING的，存在一个正在尝试连接的线程mConnectThread，则取消cancel该线程
        if (mState == STATE_CONNECTING) {
            if (mConnectThread != null) {
                mConnectThread.cancel();
                mConnectThread = null;
            }
        }

        // Cancel any thread currently running a connection
        //如存在已经连接的线程mConnectedThread，取消该线程
        if (mConnectedThread != null) {
            mConnectedThread.cancel();
            mConnectedThread = null;
        }

        // Start the thread to connect with the given device
        //开始一个新的尝试连接的线程mConnectThread
        mConnectThread = new ConnectThread(device, secure);
        mConnectThread.start();//开始该线程
        // Update UI title，更新subTitle副标题（no connected、connecting、connected）
        updateUserInterfaceTitle();
    }

    /**
     * Start the ConnectedThread to begin managing a Bluetooth connection
     *
     * @param socket The BluetoothSocket on which the connection was made
     * @param device The BluetoothDevice that has been connected
     */
    //被AcceptThread的run()调用，被AcceptThread的run又是在BluetoothChatService的start()方法被调用的
    //server和client都需要这个线程，在AcceptThread线程和ConnectedThread线程在满足一定条件时都会调用connected()创建一个ConnectedThread线程
    // TODO: 2019/1/26 因该是每点击一次消息发送按钮， server和client都会创建一个这个线程
    public synchronized void connected(BluetoothSocket socket, BluetoothDevice
            device, final String socketType) {
        Log.d(TAG, "connected, Socket Type:" + socketType);

        // Cancel the thread that completed the connection
        if (mConnectThread != null) {
            mConnectThread.cancel();
            mConnectThread = null;
        }

        // Cancel any thread currently running a connection
        if (mConnectedThread != null) {
            mConnectedThread.cancel();
            mConnectedThread = null;
        }

        // Cancel the accept thread because we only want to connect to one device
        if (mSecureAcceptThread != null) {
            mSecureAcceptThread.cancel();
            mSecureAcceptThread = null;
        }
        if (mInsecureAcceptThread != null) {
            mInsecureAcceptThread.cancel();
            mInsecureAcceptThread = null;
        }

        // Start the thread to manage the connection and perform transmissions
        // TODO: 2019/1/25 开始一个 ConnectedThread 管理connection和执行transmissions
        mConnectedThread = new ConnectedThread(socket, socketType);
        mConnectedThread.start();

        // Send the name of the connected device back to the UI Activity
        //传出一个消息到BlueToothChatFragment，Toast显示“已连接到设备的名字”
        Message msg = mHandler.obtainMessage(Constants.MESSAGE_DEVICE_NAME);
        Bundle bundle = new Bundle();
        bundle.putString(Constants.DEVICE_NAME, device.getName());
        msg.setData(bundle);
        mHandler.sendMessage(msg);
        // Update UI title
        updateUserInterfaceTitle();
    }

    /**
     * Stop all threads
     */
    public synchronized void stop() {
        Log.d(TAG, "stop");

        if (mConnectThread != null) {
            mConnectThread.cancel();
            mConnectThread = null;
        }

        if (mConnectedThread != null) {
            mConnectedThread.cancel();
            mConnectedThread = null;
        }

        if (mSecureAcceptThread != null) {
            mSecureAcceptThread.cancel();
            mSecureAcceptThread = null;
        }

        if (mInsecureAcceptThread != null) {
            mInsecureAcceptThread.cancel();
            mInsecureAcceptThread = null;
        }
        mState = STATE_NONE;
        // Update UI title
        updateUserInterfaceTitle();
    }

    /**
     * Write to the ConnectedThread in an unsynchronized manner
     *
     * @param out The bytes to write
     * @see ConnectedThread#write(byte[])
     */
    public void write(byte[] out) {
        // Create temporary object
        ConnectedThread r;
        // Synchronize a copy of the ConnectedThread
        synchronized (this) {
            if (mState != STATE_CONNECTED) return;
            r = mConnectedThread;
        }
        // Perform the write unsynchronized
       /*
       * mmOutStream= socket.getOutputStream();//ConnectedThread的write方法，通过socket获得一个输出流
       *mmOutStream.write(buffer);//输出流把数据写入到buffer
       * mHandler.obtainMessage(Constants.MESSAGE_WRITE, -1, -1, buffer).sendToTarget();//通过handler得到一个message，message把buffer的值发送到BluetoothChatFragment
       *BluetoothChatFragment得到buffer数据的值过后，把他添加到mConversationArrayAdapter.add("Me:  " + writeMessage);这就是显示到聊天记录框的内容
       * */

        r.write(out);
    }

    /**
     * Indicate that the connection attempt failed and notify the UI Activity.
     */
    //连接失败，最后会重新开启一个AcceptThread监听线程(因为本demo是蓝牙双向通信。我要做的是远程 device作为下位机开启serverSocket单向通信)
    // TODO: 2019/1/26 什么时候调用？
    //在connectThread线程使用try：mmSocket.connect()方法连接失败时，catch：会调用connectionFailed()，失败会直接return；
    //连接成功，
    // 1.服务端AcceptThread线程的socket = mmServerSocket.accept();也成功,BluetoothSocket socket不为空，进入if，进入case与语句，开启一个ConnectedThread线程
    // 2.App客户端则会执行清空连接ConnectThread进程，开启已连接ConnectedThread进程，connectThread=null;connected(mmSocket, mmDevice, mSocketType);开启一个ConnectedThread
    private void connectionFailed() {
        // Send a failure message back to the Activity
        Message msg = mHandler.obtainMessage(Constants.MESSAGE_TOAST);
        Bundle bundle = new Bundle();
        bundle.putString(Constants.TOAST, "Unable to connect device");
        msg.setData(bundle);
        mHandler.sendMessage(msg);

        mState = STATE_NONE;
        // Update UI title
        updateUserInterfaceTitle();

        // Start the service over to restart listening mode
        BluetoothChatService.this.start();
    }

    /**
     * Indicate that the connection was lost and notify the UI Activity.
     */
    //在ConnectedThread线程，发现链接失败是会调用connectionLost()
    //connectionFailed()是在connectThread线程创建连接失败调用
    //connectionLost()是在ConnectedThread线程发现已经建立的连接断开时调用
    private void connectionLost() {
        // Send a failure message back to the Activity
        Message msg = mHandler.obtainMessage(Constants.MESSAGE_TOAST);
        Bundle bundle = new Bundle();
        bundle.putString(Constants.TOAST, "Device connection was lost");
        msg.setData(bundle);
        mHandler.sendMessage(msg);

        mState = STATE_NONE;
        // Update UI title
        updateUserInterfaceTitle();

        // Start the service over to restart listening mode
        BluetoothChatService.this.start();
    }

    /**
     * This thread runs while listening for incoming connections. It behaves
     * like a server-side client. It runs until a connection is accepted
     * (or until cancelled).
     */
    //AcceptThread开放一个BluetoothServerSocket，用于监听连接请求
    private class AcceptThread extends Thread {
        // The local server socket
        private final BluetoothServerSocket mmServerSocket;
        private String mSocketType;

        //构造方法通过SDP的service name和uuid，初始化一个BluetoothServerSocket对象mmServerSocket
        //并把当前状态设置为STATE_LISTEN
        public AcceptThread(boolean secure) {
            BluetoothServerSocket tmp = null;
            mSocketType = secure ? "Secure" : "Insecure";

            // Create a new listening server socket
            try {
                if (secure) {
                    tmp = mAdapter.listenUsingRfcommWithServiceRecord(NAME_SECURE,
                            MY_UUID_SECURE);//返回一个BluetoothServerSocket
                } else {
                    tmp = mAdapter.listenUsingInsecureRfcommWithServiceRecord(
                            NAME_INSECURE, MY_UUID_INSECURE);
                }
            } catch (IOException e) {
                Log.e(TAG, "Socket Type: " + mSocketType + "listen() failed", e);
            }
            mmServerSocket = tmp;
            mState = STATE_LISTEN;
        }

        public void run() {
            Log.d(TAG, "Socket Type: " + mSocketType +
                    "BEGIN mAcceptThread" + this);
            setName("AcceptThread" + mSocketType);

            BluetoothSocket socket = null;

            // Listen to the server socket if we're not connected
            //在开放BluetoothServerSocket的监听进程AcceptThread运行时，需要先判断当前是否处于已连接状态
            //因为作为服务器，最开始是监听状态
            //未连接上会一直在循环中，通过mmServerSocket.accept()来获取一个BluetoothSocket对象socket
            //app客户端发出连接请求到开启了AcceptThread线程的服务短板，连接成功过后socket！=null，进入if语句
            //因为case STATE_LISTEN：没有加break，所以会执行到case STATE_CONNECTING:中的语句，此处有break，才会跳出switch语句
            //对switch case不加break的说明：当第二个case与switch条件相同时 执行完第二个case 然后会顺序把下面的所有case语句执行完，如果你想让程序只执行相应的case就在后面加上break，这样就只执行这一个然后跳出
            while (mState != STATE_CONNECTED) {
                try {
                    // This is a blocking call and will only return on a
                    // successful connection or an exception
                    //app客户端发起连接请求（一个ConnectedThread线程），服务端成功连接返回一个BluetoothSocket对象，客户端连接成功一会得到一个BluetoothSocket对象
                    //连接成功，
                    // 1.服务端AcceptThread线程的socket = mmServerSocket.accept();也成功,BluetoothSocket socket不为空，进入if，进入case与语句，开启一个ConnectedThread线程
                    // 2.App客户端则会执行清空连接ConnectThread进程，开启已连接ConnectedThread进程，connectThread=null;connected(mmSocket, mmDevice, mSocketType);开启一个ConnectedThread
                    socket = mmServerSocket.accept();
                } catch (IOException e) {
                    Log.e(TAG, "Socket Type: " + mSocketType + "accept() failed", e);
                    break;
                }

                // If a connection was accepted
                //如果得到了一个不为空的BluetoothSocket对象socket
                if (socket != null) {
                    synchronized (BluetoothChatService.this) {
                        switch (mState) {
                            //第一次进入是STATE_LISTEN状态，是AcceptThread线程构造方法设置的；
                            case STATE_LISTEN:
                            case STATE_CONNECTING:
                                // Situation normal. Start the connected thread.

                                // 调用connected(),建立了ConnectedThread对象
                                connected(socket, socket.getRemoteDevice(),
                                        mSocketType);
                                break;
                            case STATE_NONE:
                            case STATE_CONNECTED:
                                // Either not ready or already connected. Terminate new socket.
                                //如果已连接，退出循环，不再在上面的try语句中创建新的 socket = mmServerSocket.accept();
                                try {
                                    //关闭BluetoothSocket
                                    // TODO: 2019/1/25 有点不明白，直接退出循环就好了，为什么要socket.close()
                                    socket.close();
                                } catch (IOException e) {
                                    Log.e(TAG, "Could not close unwanted socket", e);
                                }
                                break;
                        }
                    }
                }
            }
            Log.i(TAG, "END mAcceptThread, socket Type: " + mSocketType);

        }


        public void cancel() {
            Log.d(TAG, "Socket Type" + mSocketType + "cancel " + this);
            try {
                //关闭BluetoothServerSocket
                mmServerSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "Socket Type" + mSocketType + "close() of server failed", e);
            }
        }
    }


    /**
     * This thread runs while attempting to make an outgoing connection
     * with a device. It runs straight through; the connection either
     * succeeds or fails.
     */
    //尝试与设备Device建立一个outgoing connection
        //并把当前状态设置为STATE_CONNECTING
    private class ConnectThread extends Thread {
        private final BluetoothSocket mmSocket;
        private final BluetoothDevice mmDevice;
        private String mSocketType;

        public ConnectThread(BluetoothDevice device, boolean secure) {
            mmDevice = device;
            BluetoothSocket tmp = null;
            mSocketType = secure ? "Secure" : "Insecure";

            // Get a BluetoothSocket for a connection with the
            // given BluetoothDevice
            try {
                if (secure) {
                    tmp = device.createRfcommSocketToServiceRecord(
                            MY_UUID_SECURE);
                } else {
                    tmp = device.createInsecureRfcommSocketToServiceRecord(
                            MY_UUID_INSECURE);
                }
            } catch (IOException e) {
                Log.e(TAG, "Socket Type: " + mSocketType + "create() failed", e);
            }
            mmSocket = tmp;
            //如果这是服务端程序，肯定开启了AcceptThread线程
            //AcceptThread线程中的run方法有一个循环，当设置为STATE_CONNECTING，循环里面对应的case语句字语句会被执行
            //connected(socket, socket.getRemoteDevice(),mSocketType);
            //注意ConnectThread线程中的run()方法中有一个connect()操作，会阻塞直到连接建立成功或者失败，成功则会发起connected(mmSocket, mmDevice, mSocketType);
            //在connected(mmSocket, mmDevice, mSocketType)中，会关闭其它进程，
            // TODO: 2019/1/25   若果是app客户端程序，代码没看完，后面再分析
            mState = STATE_CONNECTING;
        }

        public void run() {
            Log.i(TAG, "BEGIN mConnectThread SocketType:" + mSocketType);
            setName("ConnectThread" + mSocketType);

            // Always cancel discovery because it will slow down a connection
            mAdapter.cancelDiscovery();

            // Make a connection to the BluetoothSocket
            try {
                //This method will block until a connection is made or the connection fails.
                // If this method returns without an exception then this socket is now connected.
                //BluetoothSocket的connect()方法会阻塞block，直到连接成功或者连接失败
                //如果这个方法没有返回异常，说明mmSocket连接成功
                mmSocket.connect();
            } catch (IOException e) {
                // Close the socket
                try {
                    mmSocket.close();
                } catch (IOException e2) {
                    Log.e(TAG, "unable to close() " + mSocketType +
                            " socket during connection failure", e2);
                }
                connectionFailed();
                return;
            }

            // Reset the ConnectThread because we're done
            //对括号内的对象加锁，只有拿到对象的锁标记，才能进入代码块。
            synchronized (BluetoothChatService.this) {
                mConnectThread = null;
            }

            // Start the connected thread
            //启动一个ConnectedThread线程，在该线程中，mState会被设置为mState = STATE_CONNECTED;
            //因为这是发起连接的线程，对应APP客户端，如果不需要双向通信，app端没有开启AcceptThread线程
            connected(mmSocket, mmDevice, mSocketType);
        }

        public void cancel() {
            try {
                mmSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "close() of connect " + mSocketType + " socket failed", e);
            }
        }
    }

    /**
     * This thread runs during a connection with a remote device.
     * It handles all incoming and outgoing transmissions.
     */
    private class ConnectedThread extends Thread {
        private final BluetoothSocket mmSocket;
        private final InputStream mmInStream;
        private final OutputStream mmOutStream;

        public ConnectedThread(BluetoothSocket socket, String socketType) {
            Log.d(TAG, "create ConnectedThread: " + socketType);
            mmSocket = socket;
            InputStream tmpIn = null;
            OutputStream tmpOut = null;

            // Get the BluetoothSocket input and output streams
            try {
                tmpIn = socket.getInputStream();
                tmpOut = socket.getOutputStream();
            } catch (IOException e) {
                Log.e(TAG, "temp sockets not created", e);
            }

            mmInStream = tmpIn;
            mmOutStream = tmpOut;
            mState = STATE_CONNECTED;
        }

        public void run() {
            Log.i(TAG, "BEGIN mConnectedThread");
            byte[] buffer = new byte[1024];
            int bytes;

            // Keep listening to the InputStream while connected
            while (mState == STATE_CONNECTED) {
                try {
                    // Read from the InputStream
                    bytes = mmInStream.read(buffer);

                    // Send the obtained bytes to the UI Activity
                    mHandler.obtainMessage(Constants.MESSAGE_READ, bytes, -1, buffer)
                            .sendToTarget();
                } catch (IOException e) {
                    Log.e(TAG, "disconnected", e);
                    connectionLost();
                    break;
                }
            }
        }

        /**
         * Write to the connected OutStream.
         *
         * @param buffer The bytes to write
         */
        public void write(byte[] buffer) {
            try {
                mmOutStream.write(buffer);

                // Share the sent message back to the UI Activity
                mHandler.obtainMessage(Constants.MESSAGE_WRITE, -1, -1, buffer)
                        .sendToTarget();
            } catch (IOException e) {
                Log.e(TAG, "Exception during write", e);
            }
        }

        public void cancel() {
            try {
                mmSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "close() of connect socket failed", e);
            }
        }
    }
}

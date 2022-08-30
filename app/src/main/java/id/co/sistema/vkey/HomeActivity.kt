package id.co.sistema.vkey

import android.content.Context
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import com.vkey.android.vguard.VGException
import com.vkey.securefileio.FileOutputStream
import com.vkey.securefileio.SecureFile
import com.vkey.securefileio.SecureFileIO
import vkey.android.vos.Vos
import vkey.android.vos.VosWrapper
import java.io.File
import java.io.FileInputStream

class HomeActivity : AppCompatActivity() , VosWrapper.Callback{

    private lateinit var mVos: Vos
    private lateinit var mStartVosThread: Thread
    private lateinit var tvMessage: TextView
    private var encryptedFileLocation = ""

    companion object {
        private const val TAG = "HelloActivity"
        private const val TAG_SFIO = "SecureFileIO"
        private const val STR_INPUT = "Quick brown fox jumps over the lazy dog. 1234567890 some_one@somewhere.com"
        private const val PASSWORD = "P@ssw0rd"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_home)

        tvMessage = findViewById(R.id.tv_message)

        mVos = Vos(this)
        mVos.registerVosWrapperCallback(this)
        startVos(this)


        encryptDecryptByteFile()// berhasil
        encryptDecryptBlockData()//berhasil
        encryptDecryptStringFile()//berhasil
        encryptExistingFile()//berhasil
        writeReadEncryptedFile()
        encryptExistingFileNonText()

    }

    private fun startVos(ctx: Context) {
        mStartVosThread = Thread {
            try {
                // Get the kernel data in byte from `firmware` asset file
                val inputStream = ctx.assets.open("firmware")
                val kernelData = inputStream.readBytes()
                inputStream.read(kernelData)
                inputStream.close()

                // Start V-OS
                val vosReturnCode = mVos.start(kernelData, null, null, null, null)

                if (vosReturnCode > 0) {
                    // Successfully started V-OS
                    // Instantiate a `VosWrapper` instance for calling V-OS Processor APIs
                    val vosWrapper = VosWrapper.getInstance(ctx)
                    val version = vosWrapper.processorVersion
                    val troubleShootingID = String(vosWrapper.troubleshootingId)
                    Log.d(
                        TAG,
                        "ProcessorVers: $version || TroubleShootingID: $troubleShootingID"
                    )
                } else {
                    // Failed to start V-OS
                    Log.e(TAG, "Failed to start V-OS")
                }
            } catch (e: VGException) {
                Log.e(TAG, e.message.toString())
                e.printStackTrace()
            }
        }

        mStartVosThread.start()
    }

    private fun stopVos() {
        mVos.stop()
    }

    /**
     * SFIO OPERATIONS - Encrypt/Decrypt Block of Data
     * The APIs for encrypting and decrypting block of data are part of the SecureFileIO class.
     * */
    private fun encryptDecryptBlockData() {
        try {
            // The block of data in byte
            val input: ByteArray = STR_INPUT.toByteArray()

            // Encrypt the block of data
            val chiper: ByteArray = SecureFileIO.encryptData(input)

            // Decrypt the block encrypted block of data
            val decrypted = SecureFileIO.decryptData(chiper)
            val decryptedInput = String(decrypted)
            Log.d("blockdata", decryptedInput)
        } catch (e: Exception) {
            Log.e("blockdata", e.message.toString())
            e.printStackTrace()
        }
    }

    /**
     * SFIO OPERATIONS - Encrypting/Decrypting a String to/from a File
     * The APIs for encrypting and decrypting string to/from files are part of the SecureFileIO class.
     * */
    private fun encryptDecryptStringFile() {
        try {
            // the path to the encrypted file
            val encryptedFilePath = "${this.filesDir.absolutePath}/encryptedFile.txt"

            // Write the string to the encrypted file. If you do not wish to set a
            // password, use an empty string like "" instead. Setting the last
            // parameter to `true` will write the file atomically.
            SecureFileIO.encryptString(STR_INPUT, encryptedFilePath, PASSWORD, false)

            // Decrypt the encrypted file in the string format
            val decryptedString = SecureFileIO.decryptString(encryptedFilePath, PASSWORD)
            tvMessage.text = decryptedString
            Log.d("sfile", decryptedString)
        } catch (e: Exception) {
            Log.e("sfile", e.message.toString())
            e.printStackTrace()
        }
    }

    /**
     * SFIO OPERATIONS - Encrypting/Decrypting a Block of Data to/from a File
     * The APIs for encrypting and decrypting block data to/from files are part of the SecureFileIO class.
     * */
    private fun encryptDecryptByteFile() {
        try {
            val input = STR_INPUT.toByteArray()

            // The path to the encrypted file
            val encryptedFilePath = "${this.filesDir.absolutePath}/encryptedFile.txt"

            // Write the block data to the encrypted file. If you do not wish to set a
            // password, use an empty string like "" instead. Setting the last
            // parameter to `true` will write the file atomically.
            SecureFileIO.encryptData(input, encryptedFilePath, PASSWORD, false)

            // Decrypt the encrypted file in the byte format
            val decrypted = SecureFileIO.decryptFile(encryptedFilePath, PASSWORD)
            val decryptedResult = String(decrypted)

            Log.d("bfile", decryptedResult)
        } catch (e: Exception) {
            Log.e("bfile", e.message.toString())
            e.printStackTrace()
        }
    }

    private fun prepareFiles() {
        val dirLocation = File(applicationContext?.filesDir?.absolutePath + "/sistema")
        if(!dirLocation.exists()) dirLocation.mkdir()

        encryptedFileLocation = "$dirLocation/fileEncryption.txt"
        val file = File(encryptedFileLocation)
        if(!file.exists()) {
            Log.d("prepare","Creating new file")
            file.createNewFile()
        } else {
            Log.d("prepare","Creating new file")
        }
    }


    /**
     * SFIO OPERATIONS - Encrypting an Existing File
     * The API for encrypting an existing file is part of the SecureFileIO class.
     * */
    private fun encryptExistingFile() {
        try {
            val encryptedFilePath = "${this.filesDir.absolutePath}/encryptedFile.txt"
                createEncryptedFile(encryptedFilePath)
                java.io.FileOutputStream(encryptedFilePath).use {
                it.write(STR_INPUT.toByteArray())
                it.close()
            }


            SecureFileIO.encryptFile(encryptedFilePath , PASSWORD)
            var textString = ""
            textString = FileInputStream(encryptedFilePath)
                .bufferedReader().use { it.readText() }
            val decrypt = SecureFileIO.decryptFile(encryptedFilePath , PASSWORD)

            Log.d("existfile", "test $textString")

        } catch (e: Exception) {
            Log.e("existfile", e.message.toString())
            e.printStackTrace()
        }
    }

    private fun encryptExistingFileNonText() {
        try {
            val encryptedFilePath = "${this.filesDir.absolutePath}/wojak.jpg"
            java.io.FileOutputStream(encryptedFilePath).use {
                it.write(R.drawable.wojak)
                it.close()
            }

            SecureFileIO.encryptFile(encryptedFilePath , PASSWORD)
            val decrypt  =SecureFileIO.decryptFile(encryptedFilePath , PASSWORD)

            Log.d("existfilee", "test $decrypt")

        } catch (e: Exception) {
            Log.e("existfilee", e.message.toString())
            e.printStackTrace()
        }
    }


    private fun createEncryptedFile(filePath: String) {
        val osStream = FileOutputStream(filePath, PASSWORD)
        osStream.close()

        // Supported flags
        val flags = SecureFile.O_CREAT or SecureFile.O_TRUNC or SecureFile.O_RDWR;
        // Permissions must be given only when the flag is set for O_CREAT
        val permission =
            SecureFile.S_IRUSR or SecureFile.S_IWUSR or SecureFile.S_IRGRP or SecureFile.S_IROTH;
        val secureFile = SecureFile(filePath, PASSWORD, flags, permission)
        secureFile.close()
    }


    /**
     * SFIO OPERATIONS: Writing/Reading to/from an Encrypted File
     * The API for writing/reading to/from an encrypted file is
     * part of the FileInputStream and FileOutputStream class
     * */
    private fun writeReadEncryptedFile() {
        // If you do not wish to set a password, use an empty string
        // like "" instead. This will create the file if it does not
        // exist, and if it does, it will overwrite.
        val filePath = "${this.filesDir.absolutePath}/encryptedFile.txt"
        val ostream = FileOutputStream(filePath, PASSWORD)
        ostream.write("Hello ".toByteArray())
        ostream.write("World".toByteArray())
        ostream.close()

        // If you do not wish to set a password, use an empty string
        // like "" instead.

    }

    override fun onNotified(p0: Int, p1: Int): Boolean {
        Log.d(TAG, "onNotified: ")
        return true
    }

}
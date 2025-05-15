import kotlinx.cinterop.*
import platform.posix.*

const val EOT: UByte = 0x0u
inline val ByteArray.uByteArr: UByteArray get() = UByteArray(size) { this[it].toUByte() }

inline val String.binStr: ByteArray get() = encodeToByteArray() + EOT.toByte()
inline val String.typedBinStr: UByteArray get() = binStr.map { it.toUByte() }.toUByteArray()
inline fun Int.binArr(): ByteArray {
    val buffer = ByteArray(4)
    for (i in 0..3)
        buffer[i] = (this shr (i*8)).toByte()
    return buffer
}
inline val Int.uByteArr: UByteArray get() = binArr().toUByteArray()

@OptIn(ExperimentalForeignApi::class)
fun getUUID() {
//    // generate random bytes
//    // using POSIX API
//    val uuid = UByteArray(16)
//    val result = rand(uuid.ptr, uuid.size.toULong())
}

interface BDSFByte {
    /**
     * Byte representation of the type.
     */
    val b: UByte
}

enum class DocumentModes(override val b: UByte) : BDSFByte {
    Single(0b00u),
    Paths(0b01u)
}
val DocumentMode = DocumentModes.Paths.b

enum class Types(override val b: UByte) : BDSFByte {

    // if not specified, each type is represented as
    // {type_t *[corresponding bytes]} (braces added for clarity)
    // e.g., for UInt32 number 3: {0x08 [0x0 0x0 0x0 0x3]}

    // End of Type (actually of anything)
    EndOfType                (EOT     ),

    // bytes
    Byte                     (0x01u), // signed Byte
    Binary                   (0x02u), // array of Byte, {len_t len *[Byte]}

    // numbers (all are big endian (this is not good))
    UInt8                    (0x03u), // UByte
    Int16                    (0x04u), // Short
    UInt16                   (0x05u), // UShort
    Int32                    (0x06u), // Int
    UInt32                   (0x07u), // UInt
    Int64                    (0x08u), // Long
    UInt64                   (0x09u), // ULong
    Int128                   (0x0Au), // we will represent it as BigInteger
    UInt128                  (0x0Bu), // same as Int128
    BigInt                   (0x0Cu), // BigInteger, in binary form ends with 0x00
    UBigInt                  (0x0Du), // unsigned BigInteger

    // floating point numbers
    Float32                  (0x0Eu), // Float, 32 bits
    Double64                 (0x0Fu), // Double, 64 bits
    Decimal                  (0x10u), // Decimal, 128 bits

    // strings
    String                   (0x11u), // C-like String, ends with 0x00
    String16                 (0x12u), // reserved (deprecated)
    String32                 (0x13u), // reserved (deprecated)

    // boolean
    Bool                     (0x14u), // Bool, value is 0x00 or 0x01

    // arrays
    // note: parse it recursively; note 2: should not contain other Binaries, Arrays or Dictionaries
    DynamicArray             (0x15u), // dynamic (untyped) Array, {this_t *[item_t item] 0x00}
    TypedArray               (0x16u), // typed Array, {this_t items_t *[items] 0x00}
    Dictionary               (0x17u), // dynamic Dictionary, {this_t *[key_t key value_t value] 0x00}
    TypedDictionary          (0x18u), // typed Dictionary, {this_t key_t value_t [key value] 0x00}

    // timestamps
    UnixTimestamp            (0x19u), // Unix timestamp, 32 bits
    Timestamp64              (0x1Au), // Timestamp, 64 bits

    // null
    Null                     (0x1Bu), // Null, value is omitted

    // item IDs
    ItemID                   (0x1Cu), // ItemID, aka miniUUID, 8 bytes
    ItemID32                 (0x1Du), // ItemID that is equal to normal UUID


    // array-like types but with length (have no EOT)
    ArrayWithLength          (0x1Eu), // {this_t len_t len *[item_t items]}
    TypedArrayWithLength     (0x1Fu), // {this_t len_t len items_t *[items]}
    DictionaryWithLength     (0x20u), // {this_t len_t len [key_t key value_t value]}
    TypedDictionaryWithLength(0x21u), // {this_t len_t len key_t value_t [key value]}
    EnumValue                (0x22u), // Enum value, this_t ordinal_t value_t ordinal value
    StringWithLength         (0x23u), // {this_t len_t len*4 *[Byte]}, should be parsed like Binary and then encoded to UTF-8

    // space between 0x1C and 0xEF is available for custom types
    // (in my parser implementation its decreased to 0x23-0xEF)

    // reserved types
    Reserved0                (0xF0u),
    Reserved1                (0xF1u),
    Reserved2                (0xF2u),
    Reserved3                (0xF3u),
    Reserved4                (0xF4u),
    Reserved5                (0xF5u),
    Reserved6                (0xF6u),
    Reserved7                (0xF7u),
    Reserved8                (0xF8u),
    Reserved9                (0xF9u),
    ReservedA                (0xFAu),
    ReservedB                (0xFBu),
    ReservedC                (0xFCu),
    ReservedD                (0xFDu),
    Pair                     (0xFEu), // Pair, {this_t key_t indent_UInt}
    Document                 (0xFFu), // Document, {this_t *[Pair] 0x00}
}

val title = "Some title for the document"
val titleObject = ubyteArrayOf(
    Types.Document.b,
    *("title".typedBinStr), // key, 74 69 74 6C 65 0
        // value: type of value, then length of value (as it is a string with length),
        // then length itself and finally the string
        // 23                     6              27 (1B)               0
        Types.StringWithLength.b, Types.Int32.b, *title.length.uByteArr, *title.binStr.uByteArr,
    *("mode".typedBinStr), // key
        // value type
        Types.TypedArrayWithLength.b, Types.Int32.b, 3u.toUByte(), Types.Int32.b,
        // value
        32.toUByte(), (-8).toUByte(), 42.toUByte(),
)

val itemIdsObject = ubyteArrayOf(
    Types.Document.b,
    *"_0101010101010101".typedBinStr,
        // value type
        Types.TypedDictionaryWithLength.b, Types.Int32.b, 2u.toUByte(), EOT,
            // key and value types of dict
            Types.String.b, Types.String.b,
            // pairs
            *"foo".typedBinStr, *"bar".typedBinStr,
            *"baz".typedBinStr, *"qux".typedBinStr,
)

val docPairs = ubyteArrayOf(
    Types.Pair.b, // the first path to the first document
    // keys will be strings, and the document offset will be 72 bytes
    // and the document will be named "titles"
    Types.String.b, *"titles".typedBinStr, ((2u + 2u + 32u) * 2u).toUByte(),
    Types.Pair.b, // the second path to the second document
    // keys will be strings, and document offset will be 72+first doc length bytes
    // the name will be "items"
    Types.String.b, *"items".typedBinStr, (((2u + 2u + 32u) * 2u) + titleObject.size.toUInt()).toUByte(),
)

val bdfReferenceSeq = ubyteArrayOf(
    DocumentMode, // 0x01 means that the next block will be "Paths"
    // start of "Paths"
    *docPairs, EOT,
    // start of documents
    *titleObject, EOT,
    *itemIdsObject, EOT,
)

@OptIn(ExperimentalForeignApi::class)
fun openWriteFile(path: String, data: UByteArray) {
    // open file for writing
    val file = fopen(path, "wb")
    memScoped {
        val natData = allocArray<UByteVar>(data.size)
        data.withIndex().forEach { natData[it.index] = it.value }
        val written = fwrite(
            natData,
            sizeOf<UByteVar>().toULong(),
            data.size.toULong(),
            file
        )
        println("Written: $written of ${data.size}")
        fclose(file)
    }
}

@OptIn(ExperimentalForeignApi::class)
fun openReadFile(path: String): UByteArray {
    // open file for reading
    val file = fopen(path, "rb")
    memScoped {
        if (fseek(file, 0, SEEK_END) != 0) {
            fclose(file)
            error("Error seeking to end of file")
        }
        val size = ftell(file)
        if (size < 0) {
            fclose(file)
            error("Error obtaining file size")
        }
        fseek(file, 0, SEEK_SET)
        val natDatadata = allocArray<ByteVar>(size)
        val read = fread(
            natDatadata,
            sizeOf<ByteVar>().toULong(),
            size.toULong(),
            file
        )
        println("Read: $read of $size")
        fclose(file)
        return UByteArray(read.toInt()) {
            natDatadata[it].toUByte()
        }
    }
}

fun main() {
    var closing = true
    bdfReferenceSeq.withIndex().forEach { (i, it) ->
        if (i == docPairs.size+2 || i == docPairs.size+2+titleObject.size+1 || i == docPairs.size+2+titleObject.size+1+itemIdsObject.size+1) {
            println(); println("part")
        }
        if(closing) print("[")
        print(it.toString(16).uppercase())
        closing = false
        if (it == EOT) {
            closing = true
            println("]")
        } else {
            print(" ")
        }
    }

    println("BDSF file length: ${bdfReferenceSeq.size}, w/o header: ${bdfReferenceSeq.size-docPairs.size}")
    val sameButBson = openReadFile("test.bson")
    val sameButProtobuf = openReadFile("test.pb")
    println("Comparing to BSON: ${sameButBson.size}")
    println("Comparing to Protobuf: ${sameButProtobuf.size}")


    // write to file
    openWriteFile("test.bdf", bdfReferenceSeq)
//    openWriteFile("test.bson", sameButBson)
//    openWriteFile("test.pb", sameButProtobuf)
}
package com.signicat.services.blockchain.spi;

import java.io.IOException;
import java.util.List;

/**
 * SPI describing the actions that should be possible to do towards a Blockchain Node Network.
 */
public interface NodeNetwork {
    /**
     * Push a master key to the network. The master key will be split and distributed to the nodes.
     * @param masterKey master key to push to the node network
     * @throws IOException if something went wrong when communicating with the node network, the GUID is not unique, of the key is corrupt
     */
    void pushMasterKey(MasterKey masterKey) throws IOException;

    /**
     * Push an assertion to the node network.
     * @param assertion assertion returned from the idP
     * @return master key released from the network
     * @throws IOException if the Assertion for some reason was invalid or a communication error occurred
     */
    MasterKey pushAssertion(Assertion assertion) throws IOException;

    /**
     * Push an assertion to the node network.
     * @param assertion assertion returned from the idP, signed by this Client
     * @throws IOException if the Assertion for some reason was invalid or a communication error occurred
     */
    void pushAssertion(ClientSignedAssertion assertion) throws IOException;

    /**
     * List the block IDs on the blockchain encrypted with a given Master Key
     * @param masterKey master key the blocks belong to
     * @return list of blockchain IDs that are encrypted with the given master key
     * @throws IOException if something went wrong
     */
    List<String> listBlockIds(MasterKey masterKey) throws IOException;

    /**
     * Fetch a specific block from the blockchain.
     * @param masterKey Master key used (in part) to encrypt the block
     * @param blockId ID of block in the blockchain
     * @return Assertion stored in the blockchain
     * @throws IOException if the master key does not correspond to the block with the block with
     * the given ID, or a communication error occurred.
     */
    Assertion getBlock(MasterKey masterKey, String blockId) throws IOException;
}

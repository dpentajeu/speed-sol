
// File: TransferHelper.sol

pragma solidity ^0.6.12;

// helper methods for interacting with ERC20 tokens and sending ETH that do not consistently return true/false
library TransferHelper {
    function safeApprove(
        address token,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('approve(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x095ea7b3, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::safeApprove: approve failed'
        );
    }

    function safeTransfer(
        address token,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('transfer(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::safeTransfer: transfer failed'
        );
    }

    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('transferFrom(address,address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd, from, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::transferFrom: transferFrom failed'
        );
    }

    function safeTransferETH(address to, uint256 value) internal {
        (bool success, ) = to.call{value: value}(new bytes(0));
        require(success, 'TransferHelper::safeTransferETH: ETH transfer failed');
    }
}

// File: SafeMath.sol

pragma solidity ^0.6.12;

// ----------------------------------------------------------------------------
// Safe maths
// ----------------------------------------------------------------------------
library SafeMath {
    function add(uint a, uint b) internal pure returns (uint c) {
        c = a + b;
        require(c >= a, 'SafeMath:INVALID_ADD');
    }

    function sub(uint a, uint b) internal pure returns (uint c) {
        require(b <= a, 'SafeMath:OVERFLOW_SUB');
        c = a - b;
    }

    function mul(uint a, uint b, uint decimal) internal pure returns (uint) {
        uint dc = 10**decimal;
        uint c0 = a * b;
        require(a == 0 || c0 / a == b, "SafeMath: multiple overflow");
        uint c1 = c0 + (dc / 2);
        require(c1 >= c0, "SafeMath: multiple overflow");
        uint c2 = c1 / dc;
        return c2;
    }

    function div(uint256 a, uint256 b, uint decimal) internal pure returns (uint256) {
        require(b != 0, "SafeMath: division by zero");
        uint dc = 10**decimal;
        uint c0 = a * dc;
        require(a == 0 || c0 / a == dc, "SafeMath: division internal");
        uint c1 = c0 + (b / 2);
        require(c1 >= c0, "SafeMath: division internal");
        uint c2 = c1 / b;
        return c2;
    }
}

// File: VerifySignature.sol

pragma solidity ^0.6.12;

library VerifySignature {
    function getMessageHash(address buyer, uint counter, string memory rcode) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(buyer, counter, rcode));
    }

    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    function verify(address _signer, address buyer, uint counter, string memory rcode, bytes memory signature) public pure returns (bool) {
        bytes32 messageHash = getMessageHash(buyer, counter, rcode);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        return recoverSigner(ethSignedMessageHash, signature) == _signer;
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");
        
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

// File: Cashier.sol

pragma solidity ^0.6.12;

contract Cashier {
    using SafeMath for uint;

    uint constant TETHER_DECIMAL = 6;
    uint constant ETHER_DECIMAL  = 18;
    uint constant PER_TETHER     = 1000000;

    address public owner;            // owner who deploy the cashier
    address public payment;          // fund receive address
    address public dev;              // dev receive address
    address public tether;           // tether address
    address public signer;           // address of the validator
    bool    public is_lock;          // lock token purchase if emergency
    uint    public total_supply;     // total supply allow for user purchase token
    uint    public accm_sold;        // accumalate of token sold to user
    uint    public tether_per_token; // 1 tether to how many platform token (6 decimal)
  
    // user payment distribution (in 6 DECIMAL)
    uint public payment_rate;
    uint public owner_rate;

    mapping (address => uint) public bcounter; // the buyer transaction counter. prevent replay attack
    mapping (address => uint) public accm_amt; // accumalate token purchase amount

    event Purchase(
        address buyer,        // purchaser
        address receiver,     // receiver of platform token to be receive
        address token,        // pay currency
        uint    amount,       // input amount
        uint    purchased,    // platform token purchased success
        uint    eth_price,    // per eth to usd value
        uint    stable_price, // per usd to platform token amount (1 USD to how many platform token)
        uint    counter,      // buyer nonce
        string  rcode         // buyer referral code
    );
    event TransferOwner(address old_owner, address new_owner);
    event UpdateAddresses(address payment, address dev);
    event UpdateTokenPrice(uint tether_per_token);
    event UpdateTotalSupply(uint total_supply);

    modifier onlyOwner {
        require(msg.sender == owner, 'NOT OWNER');
        _;
    }

    constructor(
        address _signer,
        address _tether,
        address _payment,
        address _dev,
        uint    _total_supply,
        uint    _tether_per_token
    ) public {
        owner            = msg.sender;
        signer           = _signer;
        tether           = _tether;
        payment          = _payment;
        dev              = _dev;
        total_supply     = _total_supply;
        tether_per_token = _tether_per_token;

        // initial fund distribution (in 6 decimal)
        // remain 10% will distribute to dev address
        payment_rate = 850000; // 85%
        owner_rate   = 150000; // 15%
    }

    // user purchase token with tether
    function purchaseTether(address receiver, uint amount, uint counter, string memory rcode, bytes memory signature) public returns (uint) {
        require(!is_lock, 'PURCHASE LOCKED');

        address buyer = msg.sender;

        require(counter > bcounter[buyer], 'EXPIRED COUNTER'); // prevent replay attack
        require(verifyBuyer(buyer, counter, rcode, signature), 'INVALID SIGNATURE'); // validate buyer hash

        // formula: MWEI = (MWEI).mul(MWEI, 6)
        uint purchased = amount.mul(tether_per_token, TETHER_DECIMAL);

        // convert purchased unit from MWEI to WEI. contract is only using WEI as unit
        uint convert = purchased * 10**12;

        require(convert > 0, 'INVALID OUTPUT');
        require(total_supply >= (accm_sold.add(convert)), 'INSUFFICIENT SUPPLY'); // ensure sufficient supply

        TransferHelper.safeTransferFrom(tether, buyer, address(this), amount);

        bcounter[buyer] = counter;
        accm_amt[buyer] = accm_amt[buyer].add(convert);
        accm_sold       = accm_sold.add(convert);

        _processPaymentDistribution(amount);

        emit Purchase(buyer, receiver, tether, amount, convert, 0, tether_per_token, counter, rcode);
    }

    function _processPaymentDistribution(uint amount) internal {
        uint payment_amount = amount.mul(payment_rate, TETHER_DECIMAL);
        uint owner_amount   = amount.mul(owner_rate, TETHER_DECIMAL);
        uint dev_amount     = amount.sub(payment_amount).sub(owner_amount);

        if (payment_amount > 0) {
            TransferHelper.safeTransfer(tether, payment, payment_amount);
        }

        if (owner_amount > 0) {
            TransferHelper.safeTransfer(tether, owner, owner_amount);
        }

        if (dev_amount > 0) {
            TransferHelper.safeTransfer(tether, dev, dev_amount);
        }
    }

    // get estimate token amount that pay with tether
    function getTokenWithInputAmount(uint amount) public view returns(uint) {
        if (amount <= 0) {
            return 0;
        }

        // formula: MWEI = (MWEI).mul(MWEI, 6)
        uint purchased = amount.mul(tether_per_token, TETHER_DECIMAL);

        // convert purchased unit from MWEI to WEI. contract is only using WEI as unit
        uint convert = purchased * 10**12;

        return convert;
    }

    // get estimate tether price to purchase amount of token
    function getPriceWithTokenAmount(uint token_amount) public view returns(uint) {
        if (token_amount <= 0) {
            return (0);
        }

        // USD price : 1 / <usd_per_token> * <purchase token amount>
        uint token_per_usd = PER_TETHER.div(tether_per_token, TETHER_DECIMAL);
        uint result_usd    = token_amount.mul(token_per_usd * 10**12, ETHER_DECIMAL);

        // convert from wei to mwei as result is tether
        // xx limitation: result will ignore decimal after 6 decimal
        result_usd = result_usd / 10**12;

        return result_usd;
    }

    // transfer ownership. only owner executable
    function transferOwner(address new_owner) public onlyOwner {
        emit TransferOwner(owner, new_owner);
        owner = new_owner;
    }

    // update signer address. only owner executable
    function updateSigner(address new_signer) public onlyOwner {
        signer = new_signer;
    }

    // update company address. only owner executable
    function updateAddresses(address _payment, address _dev) public onlyOwner {
        payment = _payment;
        dev     = _dev;
        emit UpdateAddresses(payment, dev);
    }

    // update cashier important setting. edit wisely ! only owner executable
    function updateTotalSupply(uint _total_supply) public onlyOwner {
        total_supply = _total_supply;
        emit UpdateTotalSupply(total_supply);
    }

    // update cashier important setting. edit wisely ! only owner executable
    function updateTokenPrice(uint _tether_per_token) public onlyOwner {
        tether_per_token = _tether_per_token;
        emit UpdateTokenPrice(tether_per_token);
    }

    // update cashier purchase lock. edit wisely ! only owner executable
    function updateLock(bool status) public onlyOwner {
        is_lock = status;
    }

    // update payment distrubtion rate. edit wisely ! only owner executable
    function updateDistribution(uint _payment_rate, uint _owner_rate) public onlyOwner {
        payment_rate = _payment_rate;
        owner_rate   = _owner_rate;
    }

    // emergency transfer ether to owner. only owner executable
    function emergencyTransferEther(uint amount) public onlyOwner {
        TransferHelper.safeTransferETH(owner, amount);
    }

    // emergency transfer any token to owner. only owner executable
    function emergencyTransferToken(address token, uint amount) public onlyOwner {
        TransferHelper.safeTransfer(token, owner, amount);
    }

    // verify buyer signature
    function verifyBuyer(address buyer, uint counter, string memory rcode, bytes memory signature) private view returns (bool) {
        return VerifySignature.verify(signer, buyer, counter, rcode, signature);
    }

    fallback() external payable {
    }
}

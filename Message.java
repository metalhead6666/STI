class Message implements java.io.Serializable{
	private static final long serialVersionUID = 42L;
	private byte[] originalMessage;
	private byte[] signedMessage;
	private String alias;

	Message(byte[] originalMessage, byte[] signedMessage, String alias){
		this.originalMessage = originalMessage;
		this.signedMessage = signedMessage;
		this.alias = alias;
	}

	public byte[] getOriginalMessage(){
		return this.originalMessage;
	}

	public byte[] getSignedMessage(){
		return this.signedMessage;
	}

	public String getAlias(){
		return this.alias;
	}
}

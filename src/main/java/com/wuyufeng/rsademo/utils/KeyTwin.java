package com.wuyufeng.rsademo.utils;

public class KeyTwin {

	private String pulicModulus;
	
	private String pulicExponent;
	
	private String privatemodulus;
	
	private String privateexponent;
	
	
	public KeyTwin(String pulicModulus, String pulicExponent, String privatemodulus, String privateexponent) {
		super();
		this.pulicModulus = pulicModulus;
		this.pulicExponent = pulicExponent;
		this.privatemodulus = privatemodulus;
		this.privateexponent = privateexponent;
	}

	public String getPulicModulus() {
		return pulicModulus;
	}

	public void setPulicModulus(String pulicModulus) {
		this.pulicModulus = pulicModulus;
	}

	public String getPulicExponent() {
		return pulicExponent;
	}

	public void setPulicExponent(String pulicExponent) {
		this.pulicExponent = pulicExponent;
	}

	public String getPrivatemodulus() {
		return privatemodulus;
	}

	public void setPrivatemodulus(String privatemodulus) {
		this.privatemodulus = privatemodulus;
	}

	public String getPrivateexponent() {
		return privateexponent;
	}

	public void setPrivateexponent(String privateexponent) {
		this.privateexponent = privateexponent;
	}

	@Override
	public String toString() {
		return "KeyTwin [pulicModulus=" + pulicModulus + ", pulicExponent=" + pulicExponent + ", privatemodulus="
				+ privatemodulus + ", privateexponent=" + privateexponent + "]";
	}
	
	

}

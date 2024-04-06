import BigNumber from "bignumber.js";

export const shortenAddress = (address, len) => {
  try {
    if (len) {
      return address.slice(0, len)
    }
    return address.slice(0, 5) + "..." + address.slice(-5);
  } catch (e) {
    return address;
  }
}

export const Hex2Rgba = (hex, alpha) => {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

export const parseUcrt = (amount) => {
  return new BigNumber(amount).div(1e6).toFixed(3);
}
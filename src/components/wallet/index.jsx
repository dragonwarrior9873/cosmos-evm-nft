/* eslint-disable react/prop-types */ // TODO: upgrade to latest eslint tooling

import React, { useEffect } from "react";
import { shortenAddress } from "../../utils";
import './style.css'
import clsx from "clsx";
const DropdownButton = (props) => {
  useEffect(() => {
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [])

  const handleClickOutside = (event) => {

    if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
      setDropdownOpen(false);
    }
  }

  const dropdownRef = React.useRef(null);
  const [dropdownOpen, setDropdownOpen] = React.useState(false);

  const openDropdown = () => {
    if (!dropdownOpen)
      setDropdownOpen(true)
    else
      setDropdownOpen(false)
  }

  return (
    <div ref={dropdownRef} onClick={openDropdown} className="relative">
      <div className="wallet">
        <div className="wBalance">{props.balance}</div>
        {/* <div className="wAddress">{shortenAddress(props.address)}</div> */}
        <div className="wAddress">{props.address}</div>
      </div>
      <div className={clsx("DropdownButtonContent", dropdownOpen ? 'block' : 'hidden')} onClick={() => setDropdownOpen(false)}>
        {props.children}
      </div>
    </div>
  )
}

export const DropdownItem = (props) => {
  let { ...rest } = props
  return (
    <div className="DropdownItem" onClick={props.onClick ?? (() => { })} {...rest}>
      {props.children}
    </div>
  )
}
export default DropdownButton;

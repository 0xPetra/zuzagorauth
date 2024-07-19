import styled from 'styled-components';

// Styled components
export const OuterContainer = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100vh;
  width: 100vw;
  background-color: var(--bg-dark-primary); // Example background color, adjust as needed
`;


export const PageContainer = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 40vh;
  background-color: #ffffff;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  border-radius: 10px;
  max-width: 400px;
  width: 90%; // Ensure it takes full width up to max-width
  margin: 0 auto;
  padding: 20px;
  
  @media (min-width: 768px) {
    max-width: 600px;
    padding: 30px;
  }

  @media (min-width: 992px) {
    max-width: 800px;
    padding: 40px;
  }
`;

export const Title = styled.h1`
  font-size: 2em;
  margin-bottom: 0.5em;
  color: #1C2928;

  @media (min-width: 768px) {
    font-size: 2.5em;
  }
`;

export const Subtitle = styled.h2`
  font-size: 0.8em;
  margin-bottom: 1em;
  color: #000000;

  @media (min-width: 768px) {
    font-size: 0.8em;
  }
`;

export const CallToAction = styled.button`
  padding: 8px 16px;
  font-size: 0.9em;
  background-color: #3655f;   
  color: #ffffff;
  border: none;
  border-radius: 4px;
  cursor: pointer;

  &:hover {
    background-color: #1C2928;
  }

  @media (min-width: 768px) {
    padding: 10px 20px;
    font-size: 1em;
  }
`;
